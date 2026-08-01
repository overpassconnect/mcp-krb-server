"""--fetch and the forwarded-socket modes.

Every test here is a refusal. The successful fetch is the easy part and is
covered end to end elsewhere; these are the security properties, and each one
protects against a URL or a destination path that arrived from model output.
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
BRIDGE = ROOT / "client" / "bridge" / "mcp-krb-bridge.py"
REMOTE = ROOT / "client" / "bridge" / "mcp-krb-remote-bridge.py"
FAKE = pathlib.Path(__file__).resolve().parent          # holds fake_gssapi.py

EXIT_NO_KRB, EXIT_HTTP, EXIT_HASH, EXIT_REFUSED = 2, 3, 4, 5


def run(args, cwd=None):
    # MCP_KRB_NOAUTH is the bridge's own switch for running without a Kerberos
    # stack. Without it the module exits 2 at import on any machine lacking
    # gssapi, which is most CI runners, and no policy check would ever be
    # reached. Every refusal below happens before a socket is opened, so
    # skipping auth does not weaken what these tests prove.
    env = dict(os.environ)
    env["MCP_KRB_NOAUTH"] = "1"
    env["PYTHONPATH"] = str(FAKE) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run([sys.executable, str(BRIDGE)] + args,
                          capture_output=True, text=True, cwd=cwd, env=env)


class TestFetchPolicy(unittest.TestCase):
    """Refusals that keep a Kerberos ticket pointed somewhere sensible."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_plain_http_is_refused(self):
        # A Negotiate header in cleartext is observable, and the response is
        # unauthenticated.
        r = run(["--fetch", "http://host.example.internal/x", "-o", "a"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)
        self.assertIn("cleartext", r.stderr)

    def test_host_outside_the_realm_suffix_is_refused(self):
        r = run(["--fetch", "https://example.com/x", "-o", "a",
                 "--allow-host-suffix", ".example.internal"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)
        self.assertIn("outside the allowed suffix", r.stderr)

    @unittest.skipIf(os.name == "nt", "on native Windows such a path is correct")
    def test_windows_path_is_refused(self):
        # Inside WSL this creates a file named literally C:\... in the cwd and
        # exits 0, which is a success report with the bytes nowhere near where
        # anyone asked for them.
        r = run(["--fetch", "https://host.example.internal/x", "-o", r"C:\tmp\x",
                 "--allow-host-suffix", ".example.internal"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)
        self.assertIn("Windows path", r.stderr)

    def test_destination_outside_the_working_directory_is_refused(self):
        outside = os.path.join(tempfile.gettempdir(), "mcp-fetch-outside-probe")
        r = run(["--fetch", "https://host.example.internal/x", "-o", outside,
                 "--allow-host-suffix", ".example.internal"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)
        self.assertIn("outside the working directory", r.stderr)
        self.assertFalse(os.path.exists(outside))

    def test_existing_file_is_not_overwritten(self):
        dest = os.path.join(self.tmp, "there")
        pathlib.Path(dest).write_text("original", encoding="utf-8")
        r = run(["--fetch", "https://host.example.internal/x", "-o", "there",
                 "--allow-host-suffix", ".example.internal"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)
        self.assertEqual(pathlib.Path(dest).read_text(encoding="utf-8"), "original")

    def test_symlinked_destination_is_refused(self):
        target = os.path.join(self.tmp, "real")
        pathlib.Path(target).write_text("x", encoding="utf-8")
        link = os.path.join(self.tmp, "link")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        r = run(["--fetch", "https://host.example.internal/x", "-o", "link",
                 "--allow-host-suffix", ".example.internal"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)
        self.assertIn("symlink", r.stderr)

    def test_missing_parent_directory_is_refused_not_created(self):
        r = run(["--fetch", "https://host.example.internal/x", "-o", "nodir/x",
                 "--allow-host-suffix", ".example.internal"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)
        self.assertFalse(os.path.isdir(os.path.join(self.tmp, "nodir")))

    def test_fetch_without_output_is_an_error(self):
        r = run(["--fetch", "https://host.example.internal/x"], cwd=self.tmp)
        self.assertNotEqual(r.returncode, 0)


class TestSourceProperties(unittest.TestCase):
    """Claims about the code that are cheap to assert and expensive to lose."""

    def test_redirects_are_refused_not_followed(self):
        # http.client does not follow redirects, and inheriting that immunity is
        # the reason not to "simplify" this onto urllib or requests: forwarding
        # an Authorization header across a cross-origin redirect has a long CVE
        # history.
        src = BRIDGE.read_text(encoding="utf-8")
        self.assertIn("refusing to follow a", src)
        self.assertNotIn("import urllib.request", src)
        self.assertNotIn("import requests", src)

    def test_socket_is_chmodded_before_it_is_listened_on(self):
        src = BRIDGE.read_text(encoding="utf-8")
        bind = src[src.index("def _bind_socket"):src.index("def _peer_is_us")]
        self.assertLess(bind.index("os.chmod(path, 0o600)"), bind.index("srv.listen"),
                        "the socket must be 0600 before a single connection is accepted")

    def test_delegation_is_still_absent(self):
        # A forwarded TGT would let any fetched host act as the user. The stdio
        # path has always refused to ask for one; the fetch path shares the same
        # negotiate_header, and this asserts nobody added a flag to either.
        src = BRIDGE.read_text(encoding="utf-8")
        # The name appears in a comment explaining why it is absent, so
        # assert on the thing that would actually enable it.
        self.assertNotIn("RequirementFlag.delegate_to_peer", src)


class TestRemoteBridgeHoldsNothing(unittest.TestCase):
    """The remote end runs on a shared host. Its value is being inert."""

    def test_imports_no_crypto(self):
        src = REMOTE.read_text(encoding="utf-8")
        for forbidden in ("import gssapi", "import spnego", "import ssl", "krb5"):
            self.assertNotIn(forbidden, src,
                             "the remote bridge must hold and use no credentials")

    def test_imports_cleanly_without_any_kerberos_library(self):
        # A shared host may not have python3-gssapi at all. The bridge exits at
        # import in that case, which is exactly why this is a separate file.
        code = ("import sys; sys.modules['gssapi']=None; sys.modules['spnego']=None;"
                "import runpy; runpy.run_path(%r, run_name='not_main'); print('ok')"
                % str(REMOTE))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok", r.stdout)

    @unittest.skipIf(os.name == "nt", "the remote bridge targets Unix-socket hosts")
    def test_a_stale_socket_says_so(self):
        # The file outliving the forward is the normal look of a finished
        # session, and "connection refused" alone sends people hunting.
        with tempfile.TemporaryDirectory() as d:
            dead = os.path.join(d, "dead.sock")
            pathlib.Path(dead).write_text("", encoding="utf-8")
            r = subprocess.run([sys.executable, str(REMOTE), dead],
                               capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertTrue("stale" in r.stderr.lower() or "not exist" in r.stderr.lower(),
                            r.stderr)


if __name__ == "__main__":
    unittest.main()
