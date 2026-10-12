"""A Mac keeps the kit under "~/Library/Application Support/mcp-krb", with a space.

Two scripts word-split that path and both failed quietly:

  - install-anchor.sh expanded "--cacert $path" unquoted, so curl got a CA file
    named ".../Application" and a stray URL "Support/...". The IPA login came
    back 000, and the script told a user holding a valid ticket to kinit again.
  - setup-macos.sh kept the paths it created in a space-separated list, so the
    manifest recorded halves of paths and uninstall could match none of them.

Both are run here against a HOME that has the same space in it.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANCHOR = ROOT / "client" / "install-anchor.sh"
MACOS = (ROOT / "client" / "setup-macos.sh").read_text(encoding="utf-8")
SH = shutil.which("sh")

FAKE_KLIST = """#!/bin/sh
echo "Principal: alice@EXAMPLE.INTERNAL"
"""

# Logs its argv one per line, with a separator per call, then answers as IPA
# would: 200 for the login, the user record for user_show.
FAKE_CURL = """#!/bin/sh
for a in "$@"; do printf '%s\\n' "$a"; done >> "$CURL_LOG"
echo '--end--' >> "$CURL_LOG"
case " $* " in
    *" -w "*) printf 200 ;;
    *) printf '{"result":{"result":{"uidnumber":["1337600016"]}}}' ;;
esac
"""


def calls(log):
    out, cur = [], []
    for line in log.read_text().splitlines():
        if line == "--end--":
            out.append(cur)
            cur = []
        else:
            cur.append(line)
    return out


@unittest.skipIf(SH is None or os.name == "nt",
                 "the anchor runs on Linux and macOS; Windows runs it inside WSL")
@unittest.skipIf(os.path.exists("/opt/mcp-krb/mcp-krb-bridge.py")
                 or os.path.exists("/etc/ipa/ca.crt"),
                 "a real kit or realm CA on this host would be found first")
@unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                 "install-anchor.sh refuses to run as root")
class AnchorCaPath(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.home = self.td / "home"
        self.appdir = self.home / "Library" / "Application Support" / "mcp-krb"
        self.appdir.mkdir(parents=True)
        (self.appdir / "mcp-krb-bridge.py").write_text("")
        self.ca = self.appdir / "realm-ca.crt"
        self.ca.write_text("not a real CA\n")
        bindir = self.td / "bin"
        bindir.mkdir()
        for name, body in (("klist", FAKE_KLIST), ("curl", FAKE_CURL)):
            p = bindir / name
            p.write_text(body)
            p.chmod(0o755)
        self.log = self.td / "curl.log"
        self.env = dict(os.environ, HOME=str(self.home), CURL_LOG=str(self.log),
                        PATH=str(bindir) + os.pathsep + os.environ["PATH"])

    def test_ca_path_with_a_space_reaches_curl_as_one_argument(self):
        r = subprocess.run(
            [SH, str(ANCHOR), "--mcp-url", "https://mcp.example.internal/",
             "--domain", "example.internal",
             "--ipa-url", "https://ipa.example.internal", "--dry-run"],
            env=self.env, capture_output=True, text=True)
        self.assertIn("has IPA uid 1337600016", r.stdout, r.stderr)
        made = calls(self.log)
        self.assertEqual(len(made), 2, made)        # login, then user_show
        for argv in made:
            self.assertIn("--cacert", argv)
            self.assertEqual(argv[argv.index("--cacert") + 1], str(self.ca))
            self.assertFalse([a for a in argv if a.startswith("Support/")], argv)


def manifest_step():
    """setup-macos.sh's note_* helpers and its manifest-writing python, as text."""
    m = re.search(r"^CREATED=''\n.*?^note_replaced\(\).*?\n", MACOS, re.S | re.M)
    assert m, "setup-macos.sh note_* helpers not found"
    helpers = m.group(0)
    m = re.search(r"6\. manifest.*?python3 - <<'PYEOF'\n(.*?)^PYEOF\n", MACOS, re.S | re.M)
    assert m, "setup-macos.sh manifest heredoc not found"
    return helpers, m.group(1)


@unittest.skipIf(SH is None or shutil.which("python3") is None,
                 "no POSIX sh or python3 on PATH")
class MacosManifestPaths(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.appdir = self.td.replace(os.sep, "/") + "/Library/Application Support/mcp-krb"
        os.makedirs(self.appdir)
        self.manifest = self.appdir + "/install-manifest.json"

    def run_step(self):
        helpers, body = manifest_step()
        script = (helpers
                  + 'APPDIR="$1"; MANIFEST="$2"\n'
                  + 'note_created_dir "$APPDIR"\n'
                  + 'note_created "$APPDIR/mcp-krb-bridge.py"\n'
                  + 'note_created "$APPDIR/install-anchor.sh"\n'
                  + 'note_created /etc/resolver/example.internal\n'
                  + 'CREATED="$CREATED" CREATED_DIRS="$CREATED_DIRS" REPLACED="$REPLACED" \\\n'
                  + 'APPDIR="$APPDIR" CERT_SHA1="" MANIFEST="$MANIFEST" python3 - <<\'PYEOF\'\n'
                  + body + "PYEOF\n")
        r = subprocess.run([SH, "-c", script, "sh", self.appdir, self.manifest],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.manifest) as f:
            return json.load(f)

    def test_paths_with_a_space_are_recorded_whole(self):
        doc = self.run_step()
        self.assertEqual(doc["created"], [self.appdir + "/mcp-krb-bridge.py",
                                          self.appdir + "/install-anchor.sh",
                                          "/etc/resolver/example.internal"])
        self.assertEqual(doc["created_dirs"], [self.appdir])

    def test_halves_left_by_an_older_run_are_replaced(self):
        head, tail = self.appdir.split(" ", 1)
        with open(self.manifest, "w") as f:
            json.dump({"manifest_version": 1,
                       "created": ["/etc/resolver/example.internal", head,
                                   tail + "/mcp-krb-bridge.py"],
                       "created_dirs": [head, tail]}, f)
        doc = self.run_step()
        self.assertEqual(doc["created"], ["/etc/resolver/example.internal",
                                          self.appdir + "/mcp-krb-bridge.py",
                                          self.appdir + "/install-anchor.sh"])
        self.assertEqual(doc["created_dirs"], [self.appdir])


if __name__ == "__main__":
    unittest.main()
