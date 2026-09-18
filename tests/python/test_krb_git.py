"""krb-git: git over Kerberos from a host that holds no ticket.

Three pieces, each tested at its seam:

  - the authenticating proxy the workstation serves (`--git-listen`), driven
    one request at a time over a socketpair with the upstream faked, so every
    rule is checked without a network: realm suffix, https upgrade, CONNECT
    refused, redirects refused, the client's own Authorization dropped, the
    framing re-derived, keep-alive honoured;
  - the loopback forwarder the shared host runs (`--git-forward`), which must
    refuse any uid but its own and otherwise move bytes both ways;
  - the `krb-git` wrapper itself, run against a fake proxy on a Unix socket,
    so what git was actually told can be read back: which hosts were mapped
    and routed, and that everything else was left alone.

Hermetic like the rest of the suite: fake gssapi, no KDC, no forge.
"""
import importlib.util
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BRIDGE = ROOT / "client" / "bridge" / "mcp-krb-bridge.py"
REMOTE = ROOT / "client" / "bridge" / "mcp-krb-remote-bridge.py"
KRB_GIT = ROOT / "client" / "bridge" / "krb-git"
sys.path.insert(0, str(HERE))
import fake_gssapi  # noqa: E402


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_bridge():
    os.environ.pop("MCP_KRB_NOAUTH", None)       # the real (fake-gssapi) auth path
    fake_gssapi.reset()
    sys.modules["gssapi"] = fake_gssapi
    return load(BRIDGE, "mcp_krb_bridge_for_git")


# --- the upstream, faked ------------------------------------------------------

class FakeResponse:
    def __init__(self, status, reason, headers, body):
        self.status, self.reason = status, reason
        self._headers, self._body, self._pos = list(headers), body, 0

    def getheaders(self):
        return list(self._headers)

    def read(self, n=-1):
        if n is None or n < 0:
            n = len(self._body) - self._pos
        out = self._body[self._pos:self._pos + n]
        self._pos += len(out)
        return out


class FakeUpstream:
    """Stands in for http.client.HTTPSConnection: records what the proxy sent
    and answers with whatever the test put in `reply`."""
    made = []
    reply = (200, "OK", [("Content-Type", "text/plain"), ("Content-Length", "2")], b"ok")

    def __init__(self, host, port, context=None, timeout=None):
        self.host, self.port, self.context = host, port, context
        self.req = None
        FakeUpstream.made.append(self)

    def request(self, method, path, body=None, headers=None):
        data = b""
        if body is not None:
            data = body if isinstance(body, bytes) else b"".join(body)
        self.req = {"method": method, "path": path, "body": data,
                    "headers": dict(headers or {})}

    def getresponse(self):
        return FakeResponse(*FakeUpstream.reply)

    def close(self):
        pass


class TheProxy(unittest.TestCase):
    """`_git_forward_one`, the whole of the workstation side minus the socket."""

    @classmethod
    def setUpClass(cls):
        cls.mod = load_bridge()

    def setUp(self):
        FakeUpstream.made = []
        FakeUpstream.reply = (200, "OK", [("Content-Type", "text/plain"),
                                          ("Content-Length", "2")], b"ok")
        real = self.mod.http.client.HTTPSConnection
        self.mod.http.client.HTTPSConnection = FakeUpstream
        self.addCleanup(setattr, self.mod.http.client, "HTTPSConnection", real)

    def proxy(self, raw, suffix=".example.internal"):
        """Feed raw bytes to the proxy as git would; return everything it wrote."""
        client, server = socket.socketpair()
        client.sendall(raw)
        client.shutdown(socket.SHUT_WR)
        rd = self.mod._HttpReader(server)
        errors = []

        def serve():
            try:
                while self.mod._git_forward_one(rd, server, None, suffix):
                    pass
            except Exception as exc:                 # surfaced by the assertion below
                errors.append(exc)
            finally:
                server.close()

        t = threading.Thread(target=serve)
        t.start()
        out = b""
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            out += chunk
        t.join(5)
        client.close()
        self.assertEqual([], errors)
        return out

    GET = (b"GET http://git.example.internal/o/r.git/info/refs?service=git-upload-pack HTTP/1.1\r\n"
           b"Host: git.example.internal\r\nUser-Agent: git/2.43\r\n"
           b"Authorization: Basic Zm9vOmJhcg==\r\nProxy-Connection: Keep-Alive\r\n"
           b"Accept: */*\r\n\r\n")

    def test_connect_is_refused_before_any_connection(self):
        out = self.proxy(b"CONNECT git.example.internal:443 HTTP/1.1\r\n"
                         b"Host: git.example.internal:443\r\n\r\n")
        self.assertTrue(out.startswith(b"HTTP/1.1 405 "), out)
        self.assertEqual([], FakeUpstream.made)

    def test_a_host_outside_the_realm_is_refused_before_any_connection(self):
        out = self.proxy(b"GET http://evil.example.com/x HTTP/1.1\r\n"
                         b"Host: evil.example.com\r\n\r\n")
        self.assertTrue(out.startswith(b"HTTP/1.1 403 "), out)
        self.assertIn(b"outside the allowed suffix", out)
        self.assertEqual([], FakeUpstream.made)

    def test_a_get_is_upgraded_to_https_and_authenticated_with_the_ticket(self):
        out = self.proxy(self.GET)
        self.assertEqual(1, len(FakeUpstream.made))
        up = FakeUpstream.made[0]
        self.assertEqual(("git.example.internal", 443), (up.host, up.port))
        self.assertEqual("/o/r.git/info/refs?service=git-upload-pack", up.req["path"])
        h = up.req["headers"]
        self.assertTrue(h["Authorization"].startswith("Negotiate "),
                        "the ticket must replace whatever git was given")
        self.assertNotIn("Basic", h["Authorization"])
        self.assertEqual("git.example.internal", h["Host"])
        self.assertEqual("git/2.43", h["User-Agent"])
        self.assertNotIn("Proxy-Connection", h)
        self.assertTrue(out.startswith(b"HTTP/1.1 200 OK\r\n"), out)
        self.assertIn(b"Content-Length: 2\r\n", out)
        self.assertNotIn(b"Transfer-Encoding", out)
        self.assertTrue(out.endswith(b"\r\n\r\nok"), out)

    def test_a_port_in_the_url_is_kept(self):
        self.proxy(b"GET http://git.example.internal:8443/x HTTP/1.1\r\n"
                   b"Host: git.example.internal:8443\r\n\r\n")
        up = FakeUpstream.made[0]
        self.assertEqual(8443, up.port)
        self.assertEqual("git.example.internal:8443", up.req["headers"]["Host"])

    def test_a_redirect_is_refused_not_followed(self):
        FakeUpstream.reply = (302, "Found", [("Location", "https://elsewhere.example.com/")], b"")
        out = self.proxy(self.GET)
        self.assertTrue(out.startswith(b"HTTP/1.1 502 "), out)
        self.assertNotIn(b"Location", out)
        self.assertEqual(1, len(FakeUpstream.made), "nothing may follow the redirect")

    def test_www_authenticate_is_dropped_and_an_unframed_reply_is_chunked(self):
        FakeUpstream.reply = (401, "Unauthorized",
                              [("WWW-Authenticate", "Negotiate"), ("Content-Type", "text/plain")],
                              b"nope")
        out = self.proxy(self.GET)
        self.assertTrue(out.startswith(b"HTTP/1.1 401 Unauthorized\r\n"), out)
        self.assertNotIn(b"WWW-Authenticate", out,
                         "a 401 must read as final to git, not as an invitation")
        self.assertIn(b"Transfer-Encoding: chunked\r\n", out)
        self.assertTrue(out.endswith(b"\r\n\r\n4\r\nnope\r\n0\r\n\r\n"), out)

    def test_a_chunked_post_body_reaches_the_host_intact(self):
        out = self.proxy(b"POST http://git.example.internal/o/r.git/git-upload-pack HTTP/1.1\r\n"
                         b"Host: git.example.internal\r\nTransfer-Encoding: chunked\r\n"
                         b"Content-Type: application/x-git-upload-pack-request\r\n\r\n"
                         b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
        self.assertTrue(out.startswith(b"HTTP/1.1 200 "), out)
        up = FakeUpstream.made[0]
        self.assertEqual("POST", up.req["method"])
        self.assertEqual(b"hello world", up.req["body"])
        self.assertNotIn("Content-Length", up.req["headers"],
                         "a chunked body stays chunked; http.client frames it")
        self.assertNotIn("Transfer-Encoding", up.req["headers"])

    def test_a_post_with_a_length_keeps_it(self):
        self.proxy(b"POST http://git.example.internal/o/r.git/git-receive-pack HTTP/1.1\r\n"
                   b"Host: git.example.internal\r\nContent-Length: 11\r\n\r\nhello world")
        up = FakeUpstream.made[0]
        self.assertEqual(b"hello world", up.req["body"])
        self.assertEqual("11", up.req["headers"]["Content-Length"])

    def test_expect_100_continue_is_answered_before_the_body(self):
        out = self.proxy(b"POST http://git.example.internal/o/r.git/git-receive-pack HTTP/1.1\r\n"
                         b"Host: git.example.internal\r\nContent-Length: 3\r\n"
                         b"Expect: 100-continue\r\n\r\nabc")
        self.assertTrue(out.startswith(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 "), out)
        self.assertNotIn("Expect", FakeUpstream.made[0].req["headers"])

    def test_two_requests_on_one_connection_are_both_served(self):
        out = self.proxy(self.GET + self.GET)
        self.assertEqual(2, out.count(b"HTTP/1.1 200 OK\r\n"), out)
        self.assertEqual(2, len(FakeUpstream.made))

    def test_connection_close_ends_the_session(self):
        first = self.GET.replace(b"Proxy-Connection: Keep-Alive", b"Connection: close")
        out = self.proxy(first + self.GET)
        self.assertEqual(1, out.count(b"HTTP/1.1 200 OK\r\n"), out)
        self.assertEqual(1, len(FakeUpstream.made))

    def test_the_socket_goes_through_the_same_guarded_server(self):
        # 0600 before listen and the SO_PEERCRED check live in _serve; the git
        # listener must not grow its own accept loop around them.
        src = BRIDGE.read_text(encoding="utf-8")
        block = src[src.index("def serve_git_socket"):src.index("def serve_mcp_socket")]
        self.assertIn("_serve(path, handle)", block)
        self.assertNotIn(".accept(", block)


# --- the forwarder on the shared host -----------------------------------------

@unittest.skipIf(os.name == "nt", "the remote bridge targets Unix-socket hosts")
class TheLoopbackForwarder(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mod = load(REMOTE, "mcp_krb_remote_bridge_for_git")

    @unittest.skipUnless(os.path.exists("/proc/net/tcp"), "needs the kernel's TCP table")
    def test_the_peer_uid_is_read_from_the_kernel_table(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        cli = socket.create_connection(srv.getsockname())
        acc, _ = srv.accept()
        try:
            self.assertEqual(os.getuid(), self.mod._tcp_peer_uid(cli.getsockname()[1]))
        finally:
            for s in (acc, cli, srv):
                s.close()

    def test_a_peer_it_cannot_attribute_is_refused(self):
        # Another uid cannot be arranged in a unit test; an unattributable one
        # takes the same branch, and the branch is what matters.
        printed, logged = [], []
        real_log, real_uid = self.mod.log, self.mod._tcp_peer_uid
        self.mod.print = lambda *a, **k: printed.append(a[0])
        self.mod.log = lambda *a: logged.append(" ".join(str(x) for x in a))
        self.mod._tcp_peer_uid = lambda port: None
        self.addCleanup(delattr, self.mod, "print")
        self.addCleanup(setattr, self.mod, "log", real_log)
        self.addCleanup(setattr, self.mod, "_tcp_peer_uid", real_uid)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        threading.Thread(target=self.mod.git_forward,
                         args=(os.path.join(tmp, "never.sock"), 0), daemon=True).start()
        for _ in range(100):
            if printed:
                break
            threading.Event().wait(0.02)
        self.assertTrue(printed, "the bound port must be printed first")
        cli = socket.create_connection(("127.0.0.1", int(printed[0])), timeout=5)
        try:
            self.assertEqual(b"", cli.recv(1), "the connection must be closed unanswered")
        finally:
            cli.close()
        self.assertTrue(any("refused" in line for line in logged), logged)

    @unittest.skipUnless(os.path.exists("/proc/net/tcp"), "needs the kernel's TCP table")
    def test_the_same_uid_is_relayed_to_the_socket_both_ways(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = os.path.join(tmp, "git.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(1)

        def upper_echo():
            conn, _ = srv.accept()
            with conn:
                conn.sendall(conn.recv(64).upper())
        threading.Thread(target=upper_echo, daemon=True).start()

        p = subprocess.Popen([sys.executable, str(REMOTE), "--git-forward", path],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(p.wait)
        self.addCleanup(p.terminate)
        port = int(p.stdout.readline().strip())
        cli = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            cli.sendall(b"ping")
            self.assertEqual(b"PING", cli.recv(64))
        finally:
            cli.close()
            srv.close()


# --- the wrapper --------------------------------------------------------------

class FakeProxySocket:
    """A Unix socket that answers every HTTP request with a 500 and remembers
    the request line, which is all a test needs: whether git was routed here at
    all, and with which URL."""

    def __init__(self, path):
        self.path, self.lines, self.lock = path, [], threading.Lock()
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(8)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        with conn:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
            with self.lock:
                self.lines.append(buf.split(b"\r\n", 1)[0].decode("latin-1"))
            conn.sendall(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n"
                         b"Connection: close\r\n\r\n")

    def close(self):
        self.srv.close()


@unittest.skipIf(os.name == "nt", "krb-git is a POSIX sh script")
@unittest.skipIf(shutil.which("git") is None or shutil.which("sh") is None, "needs git and sh")
class TheWrapper(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        krb5 = os.path.join(self.tmp, "krb5.conf")
        pathlib.Path(krb5).write_text("[libdefaults]\n  default_realm = EXAMPLE.INTERNAL\n",
                                      encoding="utf-8")
        self.sock = os.path.join(self.tmp, "git.sock")
        self.proxy = FakeProxySocket(self.sock)
        self.addCleanup(self.proxy.close)
        self.env = dict(os.environ)
        self.env.update({
            "MCP_KRB_GIT_SOCKET": self.sock,
            "MCP_KRB_HOME": str(KRB_GIT.parent),
            "KRB5_CONFIG": krb5,
            "HOME": self.tmp,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        })

    def krb_git(self, *args, cwd=None, env=None):
        return subprocess.run(["sh", str(KRB_GIT)] + list(args), cwd=cwd or self.tmp,
                              env=env or self.env, capture_output=True, text=True, timeout=60)

    def repo(self, name, origin):
        path = os.path.join(self.tmp, name)
        subprocess.run(["git", "init", "-q", path], check=True, env=self.env)
        subprocess.run(["git", "-C", path, "remote", "add", "origin", origin],
                       check=True, env=self.env)
        return path

    def test_a_realm_url_is_mapped_to_http_and_routed_through_the_socket(self):
        self.krb_git("ls-remote", "https://git.example.internal/o/r.git")
        self.assertTrue(self.proxy.lines, "git never reached the proxy")
        self.assertTrue(self.proxy.lines[0].startswith(
            "GET http://git.example.internal/o/r.git/info/refs"), self.proxy.lines)

    def test_the_repository_named_by_dash_c_is_the_one_consulted(self):
        # The bug this pins: the origin used to be read from the working
        # directory, so `krb-git -C repo fetch` mapped nothing and git asked the
        # proxy for a tunnel.
        repo = self.repo("r", "https://code.example.internal/x.git")
        self.krb_git("-C", repo, "fetch")
        self.assertTrue(self.proxy.lines, "git never reached the proxy")
        self.assertIn("http://code.example.internal/x.git/info/refs", self.proxy.lines[0])
        stored = subprocess.run(["git", "-C", repo, "remote", "get-url", "origin"],
                                capture_output=True, text=True, env=self.env).stdout.strip()
        self.assertEqual("https://code.example.internal/x.git", stored,
                         "the mapping is per invocation; the stored remote must stay https")

    def test_a_host_outside_the_realm_is_left_to_git(self):
        # Nothing listens on tcp/9, so git fails at once and on its own: the
        # proxy must not have been consulted for a host it would refuse anyway.
        r = self.krb_git("ls-remote", "https://127.0.0.1:9/z.git")
        self.assertNotEqual(0, r.returncode)
        self.assertEqual([], self.proxy.lines)

    def test_a_local_command_is_plain_git(self):
        repo = self.repo("r", "https://code.example.internal/x.git")
        r = self.krb_git("-C", repo, "status", "--short")
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertEqual([], self.proxy.lines)

    def test_without_the_socket_it_is_git_with_negotiate_on(self):
        env = dict(self.env)
        env["MCP_KRB_GIT_SOCKET"] = os.path.join(self.tmp, "absent.sock")
        r = self.krb_git("config", "--get", "http.emptyAuth", env=env)
        self.assertEqual("true", r.stdout.strip(), r.stderr)
        self.assertEqual([], self.proxy.lines)

    def test_an_empty_mcp_krb_home_is_an_error_not_a_fallback(self):
        env = dict(self.env)
        env["MCP_KRB_HOME"] = self.tmp
        r = self.krb_git("--version", env=env)
        self.assertEqual(2, r.returncode)
        self.assertIn("holds no bridge", r.stderr)


if __name__ == "__main__":
    unittest.main()
