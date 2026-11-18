"""The first download on a machine that does not trust the realm CA yet.

The publisher's certificate is issued by the realm CA, and a machine that is not
enrolled has never heard of that CA. So the page's first download, setup.sh on
Linux and setup.ps1 on Windows, could never pass TLS on a fresh machine: the
Linux block fetched setup.sh with plain curl and the page called that "ordinary
public-CA TLS", and the Windows block fetched setup.ps1 with Invoke-WebRequest,
which checks Windows' own store, where nothing had put the CA yet. Only macOS
fetched the CA first. The scripts that would have installed the CA were the very
files that could not be downloaded.

So each first download is now gated on a copy of the CA fetched over plain HTTP
and checked against its SHA-256, and pinned to that copy. These tests hold the
page to that, by structure and by rendering it with the real app.js, and they run
the rendered Linux lines with a stand-in curl to show that a hash mismatch
downloads nothing.
"""
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = (ROOT / "client" / "web" / "index.html").read_text(encoding="utf-8")
APP_JS = ROOT / "client" / "web" / "app.js"
NODE = shutil.which("node")
SH = shutil.which("sh")

CODE = dict(re.findall(r'<pre><code id="([^"]+)">(.*?)</code></pre>', PAGE, re.S))

SITE = {
    "orgName": "example.internal",
    "domain": "example.internal",
    "realm": "EXAMPLE.INTERNAL",
    "kdc": "ipa.example.internal",
    "mcpUrl": "https://mcp.example.internal/",
    "caSha256": "a" * 64,
    "dnsIp": "10.0.0.53",
    "supportEmail": "",
    "downloadBase": "/d",
    "caInstall": True,
    "delegation": False,
}

# Runs the shipped app.js against the page's code blocks with just enough of a
# DOM for it to finish, and prints each block as a visitor would see it. The
# blocks are decoded the way a browser decodes them before app.js reads
# textContent.
RENDER_JS = r"""
const fs = require('fs');
const vm = require('vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const codes = input.blocks.map(b => ({ id: b[0], textContent: b[1] }));
const noop = () => {};
const element = () => ({
  setAttribute: noop, addEventListener: noop, appendChild: noop,
  classList: { add: noop, remove: noop, contains: () => false }, style: {}
});
const pres = codes.map(c => Object.assign(element(), {
  querySelector: () => c, previousElementSibling: null
}));
const ctx = {
  window: { SITE: input.site },
  document: {
    querySelectorAll: sel => sel === 'code' ? codes : (sel === 'pre' ? pres : []),
    querySelector: () => null,
    getElementById: () => null,
    createElement: element,
    body: element(),
    title: ''
  },
  location: { origin: 'https://join.example.internal', pathname: '/', hash: '' },
  navigator: { userAgent: '', platform: '' },
  history: { replaceState: noop }
};
vm.runInNewContext(fs.readFileSync(input.app, 'utf8'), ctx);
const out = {};
codes.forEach(c => { out[c.id] = c.textContent; });
process.stdout.write(JSON.stringify(out));
"""


def render(**site):
    """Every code block rendered by the real app.js with SITE plus overrides."""
    conf = dict(SITE, **site)
    blocks = [[bid, html.unescape(body)] for bid, body in CODE.items()]
    payload = json.dumps({"app": str(APP_JS), "site": conf, "blocks": blocks})
    r = subprocess.run([NODE, "-e", RENDER_JS], input=payload, capture_output=True,
                       text=True, encoding="utf-8")
    if r.returncode != 0:
        raise AssertionError("app.js did not render the page:\n%s" % r.stderr)
    return json.loads(r.stdout)


def stanza(block):
    """The text between the CA markers of a raw block, or None."""
    m = re.search(r"^__CA_BEGIN__\n(.*?)^__CA_END__\n", block, re.S | re.M)
    return m.group(1) if m else None


class TestLinuxFirstDownloadStructure(unittest.TestCase):

    def setUp(self):
        self.block = html.unescape(CODE["linux-cmd"])

    def test_the_ca_stanza_fetches_and_checks_the_ca(self):
        body = stanza(self.block)
        self.assertIsNotNone(body, "the enrolment block has no CA stanza")
        self.assertIn("curl -fsS -o realm-ca.crt http://__KDC__/ipa/config/ca.crt", body)
        self.assertIn('echo "__CA_SHA256__  realm-ca.crt" | sha256sum -c -', body)

    def test_the_check_gates_the_download(self):
        # The check's line ends in && and the line after the stanza is the
        # download, so with the markers gone the two are one command and a
        # mismatch stops it. On its own line the check would print FAILED and
        # the download would run anyway, trusting a CA nobody checked.
        lines = stanza(self.block).rstrip("\n").split("\n")
        self.assertTrue(lines[-1].rstrip().endswith("&&"),
                        "the stanza's last line must end in && so it gates the download")
        after = self.block.split("__CA_END__\n", 1)[1].split("\n", 1)[0]
        self.assertRegex(after, r"^curl --proto '=https' .*__CA_CURL_ARG__ __BASE__/setup\.sh -o setup\.sh$")

    def test_enrolment_is_handed_the_checked_ca(self):
        sudo = self.block[self.block.index("sudo sh setup.sh"):]
        self.assertIn("__CA_ENROL_ARG__", sudo)


@unittest.skipUnless(NODE, "node not available")
class TestLinuxFirstDownloadRendered(unittest.TestCase):

    def test_with_the_ca_step(self):
        text = render()["linux-cmd"]
        self.assertIn("curl -fsS -o realm-ca.crt http://ipa.example.internal/ipa/config/ca.crt\n", text)
        self.assertIn('echo "%s  realm-ca.crt" | sha256sum -c - &&\n'
                      "curl --proto '=https' --tlsv1.2 -fsS --cacert realm-ca.crt "
                      "https://join.example.internal/d/setup.sh -o setup.sh\n" % ("a" * 64), text)
        self.assertTrue(text.rstrip().endswith('--unattended --ca-cert-file="$PWD/realm-ca.crt"'))

    def test_without_the_ca_step(self):
        # A site that distributes the CA itself (caInstall false) gets the plain
        # download back and nothing that names a file that was never fetched.
        text = render(caInstall=False)["linux-cmd"]
        self.assertNotIn("realm-ca.crt", text)
        self.assertNotIn("&&", text)
        self.assertNotIn("--ca-cert-file", text)
        self.assertIn("curl --proto '=https' --tlsv1.2 -fsS ", text)

    def test_no_marker_or_token_survives_in_any_block(self):
        for mode in (True, False):
            for bid, text in render(caInstall=mode).items():
                left = re.findall(r"__[A-Z0-9_]+__", text)
                self.assertEqual([], left, "caInstall=%s, block %s still shows %s" % (mode, bid, left))


@unittest.skipUnless(NODE and SH and shutil.which("sha256sum") and os.name != "nt",
                     "needs node, sh and sha256sum on a POSIX host")
class TestLinuxFirstDownloadRuns(unittest.TestCase):
    """Runs the rendered lines before the sudo, with a stand-in curl that serves
    a fixture CA over http and records what it is asked to download over https."""

    CA = b"-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"

    FAKE_CURL = r"""#!/bin/sh
printf '%s\n' "$*" >> "$CALLS"
out=""; url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift ;;
        http://*|https://*) url="$1" ;;
    esac
    shift
done
case "$url" in
    http://*) cat "$FIXTURE" > "$out" ;;
    https://*) printf '#!/bin/sh\n' > "$out" ;;
esac
"""

    def run_lines(self, sha):
        text = render(caSha256=sha)["linux-cmd"]
        before_sudo = text.split("\nsudo ", 1)[0]
        lines = [l for l in before_sudo.split("\n") if l and not l.startswith("cd ")]
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "bin").mkdir()
            curl = d / "bin" / "curl"
            curl.write_text(self.FAKE_CURL, encoding="utf-8", newline="\n")
            curl.chmod(0o755)
            (d / "fixture.crt").write_bytes(self.CA)
            work = d / "work"
            work.mkdir()
            env = dict(os.environ, PATH="%s:%s" % (d / "bin", os.environ.get("PATH", "")),
                       CALLS=str(d / "calls"), FIXTURE=str(d / "fixture.crt"))
            r = subprocess.run([SH, "-c", "\n".join(lines)], cwd=work, env=env,
                               capture_output=True, text=True)
            calls = (d / "calls").read_text(encoding="utf-8") if (d / "calls").exists() else ""
            return r, calls, (work / "setup.sh").exists()

    def test_a_matching_hash_downloads_setup_sh_pinned_to_the_checked_ca(self):
        r, calls, got = self.run_lines(hashlib.sha256(self.CA).hexdigest())
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertTrue(got, "setup.sh was not downloaded:\n%s" % calls)
        https = [c for c in calls.splitlines() if "https://" in c]
        self.assertEqual(1, len(https), calls)
        self.assertIn("--cacert realm-ca.crt", https[0])

    def test_a_mismatched_hash_downloads_nothing(self):
        r, calls, got = self.run_lines("0" * 64)
        self.assertNotEqual(0, r.returncode)
        self.assertFalse(got, "setup.sh was downloaded although the CA did not match")
        self.assertNotIn("https://", calls)


class TestWindowsFirstDownload(unittest.TestCase):

    def setUp(self):
        self.block = html.unescape(CODE["win-cmd"])
        self.lines = self.block.split("\n")

    def test_the_ca_is_fetched_over_http_first(self):
        self.assertIn('curl.exe -fsS -o realm-ca.crt "http://__KDC__/ipa/config/ca.crt"', self.lines)

    def test_the_check_and_the_download_are_one_statement(self):
        # Lines pasted into a console run one at a time, so a check on its own
        # line could not stop the next one. The download has to sit inside the
        # if that compares the hash.
        gated = [l for l in self.lines if "setup.ps1\"" in l and "--cacert" in l]
        self.assertEqual(1, len(gated), "expected one pinned download of setup.ps1")
        self.assertRegex(gated[0],
                         r"^if \(\(Get-FileHash realm-ca\.crt\)\.Hash -eq '__CA_SHA256__'\) "
                         r"\{ curl\.exe .*--cacert realm-ca\.crt .*\"\$base/setup\.ps1\" \}$")

    def test_setup_ps1_is_never_fetched_through_windows_trust_store(self):
        # Invoke-WebRequest checks Windows' store, which has no realm CA until
        # setup.ps1 puts it there, and plain `curl` is an alias for it in
        # Windows PowerShell.
        fetches = [l for l in self.lines if "setup.ps1" in l and not l.startswith(".\\setup.ps1")]
        for l in fetches:
            self.assertNotRegex(l, r"\b(iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b", l)
            self.assertNotRegex(l, r"(^|[\s{])curl\s", l)

    def test_the_download_lands_in_a_new_folder(self):
        # A mismatch must leave nothing to run, so there can be no setup.ps1
        # from an earlier run in the folder the script is started from.
        cd = [i for i, l in enumerate(self.lines) if "New-Item -ItemType Directory" in l]
        fetch = [i for i, l in enumerate(self.lines) if "realm-ca.crt" in l]
        self.assertTrue(cd and fetch and cd[0] < fetch[0],
                        "the block must enter a new folder before it downloads anything")
        self.assertTrue(self.lines[cd[0]].startswith("cd "))


class TestNoPublicCaClaim(unittest.TestCase):

    def test_the_page_no_longer_calls_the_first_fetch_public_ca_tls(self):
        self.assertNotIn("ordinary public-CA TLS", PAGE)


if __name__ == "__main__":
    unittest.main()
