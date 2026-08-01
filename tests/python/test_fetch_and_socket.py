"""--fetch and the forwarded-socket modes.

Every test here is a refusal. The successful fetch is the easy part and is
covered end to end elsewhere; these are the security properties, and each one
protects against a URL or a destination path that arrived from model output.
"""
import os
import pathlib
import shutil
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


class TestBothWritersRefuseTheSameDestinations(unittest.TestCase):
    """mcp-fetch picks a writer by which machine it is on. The refusals must
    not depend on that choice.

    The destination checks are a copy in the remote bridge rather than an
    import, because that file has to load on a host with no Kerberos stack.
    A copy silently drifting is the obvious failure, and it is the dangerous
    one: the weaker side is the one that actually writes the file, on the
    shared host, where a path from model output is no less of a risk.
    """

    CASES = [
        ("a Windows path", lambda d: r"C:\tmp\x", "Windows path"),
        ("a symlink", None, "symlink"),
        ("a directory", None, "is a directory"),
        ("outside the working directory", None, "outside the working directory"),
        ("an existing file", None, "exists"),
    ]

    def build(self, tmp):
        """The cases that need something on disk first."""
        pathlib.Path(tmp, "real").write_text("x", encoding="utf-8")
        try:
            os.symlink(os.path.join(tmp, "real"), os.path.join(tmp, "link"))
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        os.mkdir(os.path.join(tmp, "adir"))
        pathlib.Path(tmp, "there").write_text("original", encoding="utf-8")
        return {
            "a symlink": "link",
            "a directory": "adir",
            "an existing file": "there",
            "outside the working directory":
                os.path.join(tempfile.gettempdir(), "mcp-parity-probe"),
        }

    def local(self, dest, cwd):
        return run(["--fetch", "https://h.example.internal/x", "-o", dest,
                    "--allow-host-suffix", ".example.internal"], cwd=cwd)

    def remote(self, dest, cwd):
        # No socket is needed: every one of these is decided before connecting.
        return subprocess.run(
            [sys.executable, str(REMOTE), "--fetch", "https://h.example.internal/x",
             "-o", dest, "--socket", os.path.join(cwd, "nonexistent.sock")],
            capture_output=True, text=True, cwd=cwd, timeout=30)

    @unittest.skipIf(os.name == "nt", "the remote bridge targets Unix-socket hosts")
    def test_the_two_writers_agree(self):
        for label, path_fn, expected in self.CASES:
            with self.subTest(case=label):
                tmp = tempfile.mkdtemp()
                self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
                built = self.build(tmp)
                dest = path_fn(tmp) if path_fn else built[label]

                a = self.local(dest, tmp)
                b = self.remote(dest, tmp)
                self.assertNotEqual(a.returncode, 0, "workstation accepted %s" % label)
                self.assertNotEqual(b.returncode, 0, "shared host accepted %s" % label)
                self.assertIn(expected, a.stderr + a.stdout)
                self.assertIn(expected, b.stderr + b.stdout,
                              "the remote bridge does not refuse %s the way the "
                              "workstation does" % label)
                self.assertFalse(
                    [f for f in os.listdir(tmp) if f.startswith(".mcp-fetch-")],
                    "a refusal left a temporary file behind")

    @unittest.skipIf(os.name == "nt", "the remote bridge targets Unix-socket hosts")
    def test_flags_that_change_a_destination_exist_on_both(self):
        # A flag accepted by one and an argparse error on the other makes
        # "the same command works in both places" false, which is the only
        # reason the wrapper exists.
        for flag in ("--allow-outside", "--force", "--sha256", "--max-bytes"):
            with self.subTest(flag=flag):
                a = run(["--help"])
                b = subprocess.run([sys.executable, str(REMOTE), "--help"],
                                   capture_output=True, text=True, timeout=30)
                self.assertIn(flag, a.stdout)
                self.assertIn(flag, b.stdout)


class TestOneRequestPerFetch(unittest.TestCase):
    """The socket path must not re-request what it already has.

    An earlier version fetched twice: once to measure, once to deliver. That
    made the announced digest a statement about a response the caller never
    received, so any URL that was not byte-stable failed, and the size limit
    applied only to the measuring pass.
    """

    def test_the_fetch_handler_opens_exactly_one_response(self):
        src = BRIDGE.read_text(encoding="utf-8")
        handler = src[src.index("def serve_fetch_socket"):src.index("def main")]
        self.assertEqual(handler.count("_open_response"), 1)
        self.assertNotIn("HTTPSConnection", handler,
                         "the handler must reuse _open_response, not open its own")

    def test_the_size_limit_lives_where_the_bytes_are_counted(self):
        src = BRIDGE.read_text(encoding="utf-8")
        stream = src[src.index("def _stream"):src.index("def fetch_to_file")]
        self.assertIn("max_bytes", stream)
        self.assertIn("raise FetchRefused", stream)


class TestListenRefusesToDestroy(unittest.TestCase):
    """--listen removes a stale socket. It must not remove anything else."""

    @unittest.skipIf(os.name == "nt", "Unix sockets")
    def test_a_regular_file_in_the_way_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as d:
            victim = os.path.join(d, "notes.txt")
            pathlib.Path(victim).write_text("precious", encoding="utf-8")
            r = run(["--listen", victim, "https://host.example.internal/mcp"])
            self.assertNotEqual(r.returncode, 0)
            self.assertTrue(os.path.exists(victim), "the bridge deleted a real file")
            self.assertEqual(pathlib.Path(victim).read_text(encoding="utf-8"), "precious")
            self.assertIn("not a socket", r.stderr + r.stdout)


class TestRemoteFetchWireProtocol(unittest.TestCase):
    """The remote end writes a file only when the workstation says it is whole.

    These run against a stub speaking the wire format, so they need no realm:
    the point is what the client does when the far end misbehaves.
    """

    def serve(self, script):
        import socket as _s
        import threading
        d = tempfile.mkdtemp()
        path = os.path.join(d, "s.sock")
        srv = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
        srv.bind(path)
        srv.listen(1)

        def run_once():
            conn, _ = srv.accept()
            while b"\n" not in conn.recv(4096):
                pass
            script(conn)
            conn.close()

        threading.Thread(target=run_once, daemon=True).start()
        self.addCleanup(srv.close)
        return d, path

    def client(self, path, cwd):
        # cwd matters: the destination is confined to the working directory
        # unless --allow-outside is given, exactly as on the workstation.
        return subprocess.run(
            [sys.executable, str(REMOTE), "--fetch", "https://h.example.internal/x",
             "-o", "out.bin", "--socket", path],
            capture_output=True, text=True, cwd=cwd, timeout=30)

    @unittest.skipIf(os.name == "nt", "Unix sockets")
    def test_a_complete_answer_is_written(self):
        body = b"hello world"
        import hashlib as _h
        digest = _h.sha256(body).hexdigest()

        def script(conn):
            conn.sendall(b'{"ok": true}\n')
            conn.sendall(b"%08x\r\n" % len(body) + body)
            conn.sendall(b'00000000\r\n{"ok": true, "bytes": %d, "sha256": "%s"}\n'
                         % (len(body), digest.encode()))

        d, path = self.serve(script)
        r = self.client(path, d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(pathlib.Path(d, "out.bin").read_bytes(), body)

    @unittest.skipIf(os.name == "nt", "Unix sockets")
    def test_a_stream_that_stops_before_the_trailer_writes_nothing(self):
        # What a mid-fetch failure on the workstation looks like from here.
        def script(conn):
            conn.sendall(b'{"ok": true}\n')
            conn.sendall(b"%08x\r\n" % 4 + b"part")

        d, path = self.serve(script)
        r = self.client(path, d)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(d, "out.bin")))
        self.assertFalse([f for f in os.listdir(d) if f.startswith(".mcp-fetch-")])

    @unittest.skipIf(os.name == "nt", "Unix sockets")
    def test_an_abort_trailer_is_reported_and_nothing_is_written(self):
        def script(conn):
            conn.sendall(b'{"ok": true}\n')
            conn.sendall(b"%08x\r\n" % 4 + b"part")
            conn.sendall(b'00000000\r\n{"ok": false, "error": "too big"}\n')

        d, path = self.serve(script)
        r = self.client(path, d)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("too big", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(d, "out.bin")))


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
