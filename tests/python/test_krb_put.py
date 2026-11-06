"""krb-put: a file or folder into a WebDAV folder over Kerberos.

A write can do what a read cannot, so the refusals come first and each one
checks that nothing reached the server. The rest runs the real sender against
a WebDAV server held in memory, including one that lies about what it stored:
a send is only a success when the server has confirmed every name and size.
"""
import importlib.util
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from urllib.parse import quote, unquote, urlsplit

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BRIDGE = ROOT / "client" / "bridge" / "mcp-krb-bridge.py"
KRB_PUT = ROOT / "client" / "bridge" / "krb-put"
sys.path.insert(0, str(HERE))
import fake_gssapi  # noqa: E402

EXIT_NO_KRB, EXIT_REFUSED = 2, 5
URL = "https://files.example.internal/dav/me/"


def load_bridge():
    os.environ.pop("MCP_KRB_NOAUTH", None)       # the real (fake-gssapi) auth path
    fake_gssapi.reset()
    sys.modules["gssapi"] = fake_gssapi
    spec = importlib.util.spec_from_file_location("mcp_krb_bridge_for_put", str(BRIDGE))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(args, cwd=None):
    env = dict(os.environ)
    env["MCP_KRB_NOAUTH"] = "1"
    return subprocess.run([sys.executable, str(BRIDGE)] + args,
                          capture_output=True, text=True, cwd=cwd, env=env)


# --- the server, faked --------------------------------------------------------

class FakeResponse:
    def __init__(self, status, body=b"", headers=()):
        self.status, self.reason, self._body = status, "x", body
        self._headers = list(headers)

    def getheaders(self):
        return list(self._headers)

    def read(self):
        return self._body


class FakeDav:
    """A WebDAV server in memory. Folders are paths ending in '/', files map to
    their bytes. The switches make it misbehave the ways a real one can."""

    def __init__(self):
        self.tree = {"/dav/": None, "/dav/me/": None}
        self.requests = []
        self.sessions = 0
        self.truncate = None         # keep this file one byte short
        self.lose = None             # accept this file, then not have it
        self.redirect = None         # answer this method with a 302
        self.refuse_put_after = None
        self.drop_next = False       # the keep-alive connection went away

    def handle(self, method, path, body, headers):
        self.requests.append({"method": method, "path": path, "headers": dict(headers),
                              "body": body})
        cookies = []
        if "nc_session=abc" not in headers.get("Cookie", ""):
            self.sessions += 1
            cookies = [("Set-Cookie", "nc_session=abc; Path=/; Secure; HttpOnly")]
        if method == self.redirect:
            return FakeResponse(302, headers=[("Location", "https://elsewhere.example.com/")])
        name = unquote(path)
        if method == "PROPFIND":
            return self.propfind(name, headers["Depth"], cookies)
        if method == "MKCOL":
            if name in self.tree:
                return FakeResponse(405, headers=cookies)
            self.tree[name] = None
            return FakeResponse(201, headers=cookies)
        if method == "PUT":
            puts = sum(1 for r in self.requests if r["method"] == "PUT")
            if self.refuse_put_after is not None and puts > self.refuse_put_after:
                return FakeResponse(507, headers=cookies)
            if name.rsplit("/", 1)[0] + "/" not in self.tree:
                return FakeResponse(409, headers=cookies)
            existed = name in self.tree
            data = b"".join(body) if body is not None else b""
            if self.truncate and name.endswith(self.truncate):
                data = data[:-1]
            if not (self.lose and name.endswith(self.lose)):
                self.tree[name] = data
            return FakeResponse(204 if existed else 201, headers=cookies)
        return FakeResponse(405, headers=cookies)

    def propfind(self, name, depth, cookies):
        as_folder = name.rstrip("/") + "/"
        key = as_folder if as_folder in self.tree else name.rstrip("/")
        if key not in self.tree:
            return FakeResponse(404, headers=cookies)
        items = [key]
        if depth == "1" and key.endswith("/"):
            items += [p for p in self.tree
                      if p != key and p.startswith(key) and "/" not in p[len(key):].rstrip("/")]
        out = ['<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">']
        for p in items:
            folder = p.endswith("/")
            prop = "<d:resourcetype><d:collection/></d:resourcetype>" if folder else \
                "<d:resourcetype/><d:getcontentlength>%d</d:getcontentlength>" % len(self.tree[p])
            out.append("<d:response><d:href>%s</d:href><d:propstat><d:prop>%s</d:prop>"
                       "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
                       % (quote(p), prop))
        out.append("</d:multistatus>")
        return FakeResponse(207, "".join(out).encode(), cookies)


class FakeConnection:
    server = None
    made = 0

    def __init__(self, host, port, context=None, timeout=None):
        FakeConnection.made += 1
        self.host = host
        self.reply = None

    def request(self, method, path, body=None, headers=None):
        srv = FakeConnection.server
        if srv.drop_next:
            srv.drop_next = False
            self.reply = None
            return
        self.reply = srv.handle(method, path, body, headers or {})

    def getresponse(self):
        if self.reply is None:
            raise FakeConnection.mod.http.client.RemoteDisconnected("gone")
        return self.reply

    def close(self):
        pass


class SenderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_bridge()
        FakeConnection.mod = cls.mod

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.srv = FakeDav()
        FakeConnection.server = self.srv
        FakeConnection.made = 0
        real = self.mod.http.client.HTTPSConnection
        self.mod.http.client.HTTPSConnection = FakeConnection
        self.addCleanup(setattr, self.mod.http.client, "HTTPSConnection", real)

    def write(self, rel, data=b"data"):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def folder(self):
        """kit/ with a file, a nested file, an empty folder and a Greek name."""
        self.write("kit/brief.md", b"hello")
        self.write("kit/screens/one two.png", b"x" * 70000)
        self.write("kit/\u03b1\u03c1\u03c7\u03b5\u03af\u03bf.txt", b"greek")
        os.makedirs(os.path.join(self.tmp, "kit", "posts"))
        return os.path.join(self.tmp, "kit")

    def send(self, source, url=URL, replace=False):
        return self.mod.put_tree(self.mod._put_plan(source), url, replace=replace)

    def writes(self):
        return [r for r in self.srv.requests if r["method"] in ("PUT", "MKCOL")]


class Sending(SenderTest):

    def test_a_file_lands_in_the_folder_under_its_own_name(self):
        path = self.write("report.pdf", b"12345")
        self.assertEqual(self.send(path), (1, 0, 5))
        self.assertEqual(self.srv.tree["/dav/me/report.pdf"], b"12345")

    def test_a_folder_arrives_whole_with_its_empty_folders(self):
        self.assertEqual(self.send(self.folder()), (3, 3, 70010))
        tree = self.srv.tree
        self.assertEqual(tree["/dav/me/kit/brief.md"], b"hello")
        self.assertEqual(len(tree["/dav/me/kit/screens/one two.png"]), 70000)
        self.assertEqual(tree["/dav/me/kit/\u03b1\u03c1\u03c7\u03b5\u03af\u03bf.txt"], b"greek")
        self.assertIn("/dav/me/kit/posts/", tree)

    def test_names_are_encoded_on_the_wire(self):
        self.send(self.folder())
        paths = [r["path"] for r in self.srv.requests]
        self.assertIn("/dav/me/kit/screens/one%20two.png", paths)
        self.assertTrue(all(p.isascii() and " " not in p for p in paths))

    def test_a_decomposed_name_is_sent_composed(self):
        # What macOS stores. Sent as it is, a server that composes it would
        # report another name and a good send would look like a failure.
        decomposed = unicodedata.normalize("NFD", "caf\u00e9.txt")
        self.write(decomposed)
        self.send(os.path.join(self.tmp, decomposed))
        self.assertIn("/dav/me/caf\u00e9.txt", self.srv.tree)

    def test_a_destination_written_with_a_space_or_escape_both_work(self):
        self.srv.tree["/dav/me/My Folder/"] = None
        path = self.write("a.txt")
        self.send(path, URL + "My Folder")
        self.send(path, URL + "My%20Folder/", replace=True)
        self.assertIn("/dav/me/My Folder/a.txt", self.srv.tree)

    def test_a_file_is_streamed_rather_than_read_whole(self):
        self.send(self.write("big.bin", b"y" * 200000))
        put = [r for r in self.srv.requests if r["method"] == "PUT"][0]
        self.assertNotIsInstance(put["body"], (bytes, bytearray))
        self.assertEqual(put["headers"]["Content-Length"], "200000")

    def test_an_empty_file_is_still_a_file(self):
        self.assertEqual(self.send(self.write("empty.txt", b"")), (1, 0, 0))
        self.assertEqual(self.srv.tree["/dav/me/empty.txt"], b"")

    def test_every_request_carries_its_own_negotiate_header(self):
        fake_gssapi.reset()
        self.send(self.folder())
        for r in self.srv.requests:
            self.assertTrue(r["headers"]["Authorization"].startswith("Negotiate "))
        self.assertEqual(len(fake_gssapi.contexts), len(self.srv.requests))

    def test_a_folder_of_files_opens_one_session(self):
        # Nextcloud opens a session per authenticated request that brings no
        # cookie, so a run without a jar leaves one per file behind.
        self.send(self.folder())
        self.assertEqual(self.srv.sessions, 1)

    def test_a_cookie_the_server_withdraws_is_not_sent_again(self):
        dav = self.mod._Dav(URL)
        dav._keep_cookies(FakeResponse(200, headers=[
            ("Set-Cookie", "keep=1; Path=/"), ("Set-Cookie", "gone=2; Path=/")]))
        dav._keep_cookies(FakeResponse(200, headers=[
            ("Set-Cookie", "gone=deleted; Max-Age=0; Path=/")]))
        self.assertEqual(dav.cookies, {"keep": "1"})

    def test_one_connection_serves_the_whole_run(self):
        self.send(self.folder())
        self.assertEqual(FakeConnection.made, 1)

    def test_listings_send_no_body(self):
        # An empty PROPFIND means allprop, and a relay that forwards bodies only
        # for POST, PUT and PATCH must be able to carry it unchanged.
        self.send(self.folder())
        for r in self.srv.requests:
            if r["method"] == "PROPFIND":
                self.assertIsNone(r["body"])

    def test_a_dropped_connection_is_retried_once(self):
        path = self.write("a.txt", b"12345")
        self.srv.drop_next = True
        self.assertEqual(self.send(path), (1, 0, 5))
        self.assertEqual(FakeConnection.made, 2)


class Refusals(SenderTest):

    def test_an_existing_file_is_not_written_over(self):
        self.srv.tree["/dav/me/a.txt"] = b"precious"
        with self.assertRaises(self.mod.FetchRefused):
            self.send(self.write("a.txt", b"new"))
        self.assertEqual(self.srv.tree["/dav/me/a.txt"], b"precious")
        self.assertEqual(self.writes(), [])

    def test_an_existing_folder_is_not_merged_into(self):
        self.srv.tree["/dav/me/kit/"] = None
        with self.assertRaises(self.mod.FetchRefused):
            self.send(self.folder())
        self.assertEqual(self.writes(), [])

    def test_a_folder_that_appears_during_the_run_stops_it(self):
        # Top level free when checked, something inside it there by the time it
        # is created: someone else got in between, and it may not be written over.
        kit = self.folder()
        self.srv.tree["/dav/me/kit/posts/"] = None
        with self.assertRaises(RuntimeError) as caught:
            self.send(kit)
        self.assertIn("HTTP 405", str(caught.exception))
        self.assertEqual([r for r in self.srv.requests if r["method"] == "PUT"], [])

    def test_replace_writes_over_and_keeps_what_else_is_there(self):
        kit = self.folder()
        self.send(kit)
        self.srv.tree["/dav/me/kit/theirs.txt"] = b"not ours"
        self.write("kit/brief.md", b"changed")
        self.send(kit, replace=True)
        self.assertEqual(self.srv.tree["/dav/me/kit/brief.md"], b"changed")
        self.assertEqual(self.srv.tree["/dav/me/kit/theirs.txt"], b"not ours")

    def test_a_missing_destination_fails_and_creates_nothing(self):
        with self.assertRaises(RuntimeError):
            self.send(self.folder(), URL + "tpyo/")
        self.assertEqual(self.writes(), [])

    def test_a_destination_that_is_a_file_is_refused(self):
        self.srv.tree["/dav/me/a.txt"] = b"x"
        with self.assertRaises(self.mod.FetchRefused):
            self.send(self.write("b.txt"), URL + "a.txt")
        self.assertEqual(self.writes(), [])

    def test_a_redirect_is_never_followed(self):
        self.srv.redirect = "PROPFIND"
        with self.assertRaises(self.mod.FetchRefused):
            self.send(self.write("a.txt"))
        self.assertEqual(len(self.srv.requests), 1)
        self.assertEqual(self.writes(), [])

    def test_a_redirected_upload_is_not_repeated_elsewhere(self):
        self.srv.redirect = "PUT"
        with self.assertRaises(self.mod.FetchRefused):
            self.send(self.write("a.txt"))
        self.assertEqual(len([r for r in self.srv.requests if r["method"] == "PUT"]), 1)

    def test_a_symlink_inside_the_folder_stops_it_before_anything_is_sent(self):
        kit = self.folder()
        outside = self.write("secret.txt", b"not for sending")
        os.symlink(outside, os.path.join(kit, "link.txt"))
        with self.assertRaises(self.mod.FetchRefused) as caught:
            self.send(kit)
        self.assertIn("is a symlink", str(caught.exception))
        self.assertEqual(self.srv.requests, [])

    def test_a_symlinked_folder_is_not_walked_into(self):
        kit = self.folder()
        os.symlink(self.tmp, os.path.join(kit, "loop"))
        with self.assertRaises(self.mod.FetchRefused):
            self.send(kit)

    def test_the_source_itself_may_not_be_a_symlink(self):
        link = os.path.join(self.tmp, "link")
        os.symlink(self.write("a.txt"), link)
        with self.assertRaises(self.mod.FetchRefused):
            self.send(link)

    def test_a_pipe_is_not_a_file(self):
        kit = self.folder()
        os.mkfifo(os.path.join(kit, "pipe"))
        with self.assertRaises(self.mod.FetchRefused):
            self.send(kit)

    def test_a_refused_put_stops_the_run_and_says_how_far_it_got(self):
        self.srv.refuse_put_after = 1
        with self.assertRaises(RuntimeError) as caught:
            self.send(self.folder())
        self.assertIn("after 1 of 3 files", str(caught.exception))
        self.assertEqual(len([r for r in self.srv.requests if r["method"] == "PUT"]), 2)


class TheCheckAtTheEnd(SenderTest):

    def test_a_short_file_on_the_server_fails_the_run(self):
        self.srv.truncate = "brief.md"
        with self.assertRaises(self.mod.PutMismatch) as caught:
            self.send(self.folder())
        self.assertIn("kit/brief.md: 5 bytes sent, server says 4", str(caught.exception))

    def test_a_file_the_server_lost_fails_the_run(self):
        self.srv.lose = "one two.png"
        with self.assertRaises(self.mod.PutMismatch) as caught:
            self.send(self.folder())
        self.assertIn("kit/screens/one two.png: not there", str(caught.exception))

    def test_an_empty_folder_is_checked_too(self):
        kit = self.folder()
        real = self.srv.handle

        def forget_posts(method, path, body, headers):
            answer = real(method, path, body, headers)
            if method == "MKCOL" and path.endswith("posts/"):
                del self.srv.tree["/dav/me/kit/posts/"]
            return answer
        self.srv.handle = forget_posts
        with self.assertRaises(self.mod.PutMismatch):
            self.send(kit)

    def test_a_folder_that_came_back_as_a_file_fails_the_run(self):
        entries = [("/dav/me/kit", False, 9)]
        self.mod._dav_entries, real = (lambda _b: entries), self.mod._dav_entries
        self.addCleanup(setattr, self.mod, "_dav_entries", real)
        dav = self.mod._Dav(URL)
        with self.assertRaises(self.mod.PutMismatch):
            self.srv.tree["/dav/me/kit"] = b"x"
            self.mod._put_verify(dav, "/dav/me/", ["kit"], [])

    def test_a_file_that_shrinks_during_the_send_fails_the_run(self):
        path = self.write("a.txt", b"12345")
        chunks = self.mod._file_chunks(path, 10)
        with self.assertRaises(self.mod.PutMismatch):
            list(chunks)

    def test_a_property_the_server_says_is_missing_is_not_a_size(self):
        body = (b'<d:multistatus xmlns:d="DAV:"><d:response><d:href>/x</d:href>'
                b'<d:propstat><d:prop><d:getcontentlength>7</d:getcontentlength></d:prop>'
                b'<d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>'
                b'</d:response></d:multistatus>')
        self.assertEqual(self.mod._dav_entries(body), [("/x", False, None)])

    def test_a_full_url_in_href_is_read_as_a_path(self):
        body = (b'<d:multistatus xmlns:d="DAV:"><d:response>'
                b'<d:href>https://h.example.internal/a%20b/</d:href>'
                b'<d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>'
                b'<d:status>HTTP/1.1 200 OK</d:status></d:propstat>'
                b'</d:response></d:multistatus>')
        self.assertEqual(self.mod._dav_entries(body), [("/a b", True, None)])


class ThePolicy(unittest.TestCase):
    """The command line, before any socket: exit codes and refusals."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        with open(os.path.join(self.tmp, "a.txt"), "w") as fh:
            fh.write("x")

    def test_plain_http_is_refused(self):
        r = run(["--put", "a.txt", "http://host.example.internal/dav/"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)
        self.assertIn("cleartext", r.stderr)

    def test_a_host_outside_the_realm_is_refused(self):
        r = run(["--put", "a.txt", "https://example.com/dav/",
                 "--allow-host-suffix", ".example.internal"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)
        self.assertIn("outside the allowed suffix", r.stderr)

    def test_a_query_is_refused(self):
        r = run(["--put", "a.txt", "https://host.example.internal/dav/?x=1",
                 "--allow-host-suffix", ".example.internal"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)

    def test_a_missing_source_is_refused(self):
        r = run(["--put", "nothing.txt", "https://host.example.internal/dav/",
                 "--allow-host-suffix", ".example.internal"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)
        self.assertIn("no such file", r.stderr)

    @unittest.skipIf(os.name == "nt", "on native Windows such a path is correct")
    def test_a_windows_path_is_refused(self):
        r = run(["--put", r"C:\tmp\kit", "https://host.example.internal/dav/",
                 "--allow-host-suffix", ".example.internal"], cwd=self.tmp)
        self.assertEqual(r.returncode, EXIT_REFUSED)
        self.assertIn("wslpath", r.stderr)


@unittest.skipIf(os.name == "nt", "krb-put is a POSIX sh script")
class TheWrapper(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        with open(os.path.join(self.tmp, "mcp-krb-bridge.py"), "w") as fh:
            fh.write("import sys\nprint(' '.join(sys.argv[1:]))\n")

    def wrapper(self, *args, socket_path=None):
        env = dict(os.environ)
        env["MCP_KRB_HOME"] = self.tmp
        env["MCP_KRB_GIT_SOCKET"] = socket_path or os.path.join(self.tmp, "absent.sock")
        return subprocess.run(["sh", str(KRB_PUT)] + list(args),
                              capture_output=True, text=True, env=env, timeout=30)

    def test_it_hands_its_arguments_to_the_bridge(self):
        r = self.wrapper("kit", URL, "--replace")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "--put kit %s --replace" % URL)

    def test_an_empty_home_is_an_error(self):
        os.unlink(os.path.join(self.tmp, "mcp-krb-bridge.py"))
        r = self.wrapper("kit", URL)
        self.assertEqual(r.returncode, EXIT_NO_KRB)
        self.assertIn("krb-put: MCP_KRB_HOME=", r.stderr)

    def test_on_a_shared_host_it_says_so_and_never_suggests_kinit(self):
        path = os.path.join(self.tmp, "git.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        self.addCleanup(srv.close)
        r = self.wrapper("kit", URL, socket_path=path)
        self.assertEqual(r.returncode, EXIT_NO_KRB)
        self.assertIn("shared host", r.stderr)
        self.assertNotIn("kinit", r.stderr)
        self.assertEqual(r.stdout, "")


if __name__ == "__main__":
    unittest.main()
