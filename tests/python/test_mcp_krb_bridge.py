"""Unit tests for mcp-krb-bridge.py (the stdio bridge client). Traceability in
../../SECURITY.md, section "The test suite".
Run:  python -m unittest -v  (from tests/python)"""
import importlib.util
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
BRIDGE = os.path.join(REPO, 'client', 'bridge', 'mcp-krb-bridge.py')
sys.path.insert(0, HERE)
import fake_gssapi  # noqa: E402


def load_bridge():
    os.environ.pop('MCP_KRB_NOAUTH', None)      # want the real (fake-gssapi) auth path
    fake_gssapi.reset()
    sys.modules['gssapi'] = fake_gssapi
    spec = importlib.util.spec_from_file_location('mcp_krb_bridge', BRIDGE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- http.client doubles ----------------------------------------------------
class FakeResp:
    def __init__(self, status=200, body=b'', ctype='application/json', headers=None):
        self.status = status
        self._body = body
        self._headers = dict(headers or {})
        if ctype:
            self._headers.setdefault('Content-Type', ctype)

    def getheader(self, k, default=None):
        for kk, vv in self._headers.items():
            if kk.lower() == k.lower():
                return vv
        return default

    def read(self, *a):
        return self._body


class FakeConn:
    def __init__(self, resp):
        self.resp = resp
        self.requests = []
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        self.requests.append({'method': method, 'path': path, 'body': body, 'headers': dict(headers or {})})

    def getresponse(self):
        return self.resp

    def close(self):
        self.closed = True


class FakeSSEResp:
    def __init__(self, lines):
        self._lines = [l.encode() for l in lines] + [b'']

    def getheader(self, k, default=None):
        return 'text/event-stream' if k.lower() == 'content-type' else default

    def readline(self):
        return self._lines.pop(0) if self._lines else b''

    def read(self, *a):
        return b''


mod = load_bridge()


class UrlParsing(unittest.TestCase):
    def test_https_ok(self):
        b = mod.Bridge('https://mcp.x.internal/')
        self.assertTrue(b.https)
        self.assertEqual(b.host, 'mcp.x.internal')
        self.assertEqual(b.port, 443)
        self.assertEqual(b.path, '/')

    def test_port_and_query_preserved(self):
        b = mod.Bridge('https://mcp.x.internal:8443/mcp?tenant=a')
        self.assertEqual(b.port, 8443)
        self.assertEqual(b.path, '/mcp?tenant=a')

    def test_http_nonlocal_refused(self):   # [CL1]
        with self.assertRaises(SystemExit):
            mod.Bridge('http://mcp.x.internal/')

    def test_http_localhost_allowed(self):
        b = mod.Bridge('http://127.0.0.1:8899/')
        self.assertFalse(b.https)
        self.assertEqual(b.port, 8899)

    def test_bad_scheme_refused(self):
        with self.assertRaises(SystemExit):
            mod.Bridge('ftp://mcp.x.internal/')


class HeaderConstruction(unittest.TestCase):
    def setUp(self):
        fake_gssapi.reset()
        self.b = mod.Bridge('https://mcp.x.internal/')
        self.created = []

        def fake_connect():
            c = FakeConn(FakeResp())
            self.created.append(c)
            return c
        self.b._connect = fake_connect

    def test_authorization_header_present(self):   # RFC 4559 §4 Negotiate header
        conn, _ = self.b._post('{"jsonrpc":"2.0","id":1,"method":"initialize"}')
        h = conn.requests[0]['headers']
        self.assertTrue(h['Authorization'].startswith('Negotiate '))
        self.assertIn('application/json', h['Accept'])
        self.assertEqual(h['Content-Type'], 'application/json')

    def test_session_and_protocol_headers(self):
        self.b.session_id = 'SID-123'
        self.b.protocol_version = '2025-06-18'
        conn, _ = self.b._post('{}')
        h = conn.requests[0]['headers']
        self.assertEqual(h['Mcp-Session-Id'], 'SID-123')
        self.assertEqual(h['MCP-Protocol-Version'], '2025-06-18')

    def test_fresh_token_per_request(self):   # RFC 4120 §3.2.2
        self.b._post('{}')
        self.b._post('{}')
        self.assertGreaterEqual(len(fake_gssapi.contexts), 2)
        self.assertNotEqual(fake_gssapi.contexts[-1].serial, fake_gssapi.contexts[-2].serial)


class ForwardBody(unittest.TestCase):
    def setUp(self):
        self.b = mod.Bridge('https://mcp.x.internal/')
        self.out = []
        self.b._emit = lambda text: self.out.append(text)

    def test_valid_json_forwarded_minified(self):
        self.b._forward_body('{"jsonrpc": "2.0", "id": 1, "result": {}}', emit=True)
        self.assertEqual(len(self.out), 1)
        self.assertNotIn(' ', self.out[0])   # minified

    def test_non_json_dropped(self):
        self.b._forward_body('this is not json', emit=True)
        self.assertEqual(self.out, [])

    def test_protocol_version_sniffed(self):
        self.b._forward_body('{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}', emit=False)
        self.assertEqual(self.b.protocol_version, '2025-06-18')


class SSE(unittest.TestCase):
    def setUp(self):
        self.b = mod.Bridge('https://mcp.x.internal/')
        self.out = []
        self.b._emit = lambda text: self.out.append(text)

    def test_parses_events_ignores_comments(self):
        resp = FakeSSEResp([
            ': keepalive\n',
            'event: message\n',
            'data: {"jsonrpc":"2.0","method":"notifications/message"}\n',
            '\n',
            'data: {"jsonrpc":"2.0","id":2,"result":{}}\n',
            '\n',
        ])
        self.b._consume_sse(resp, emit=True)
        self.assertEqual(len(self.out), 2)
        self.assertIn('notifications/message', self.out[0])
        self.assertIn('"id":2', self.out[1])


class Roundtrip(unittest.TestCase):
    def setUp(self):
        self.b = mod.Bridge('https://mcp.x.internal/')
        self.out = []
        self.b._emit = lambda text: self.out.append(text)

    def _post_returns(self, resp):
        self.b._post = lambda raw: (FakeConn(resp), resp)

    def test_202_no_output(self):
        self._post_returns(FakeResp(status=202, body=b''))
        self.b._roundtrip('{"jsonrpc":"2.0","method":"notifications/initialized"}', None, 'notifications/initialized')
        self.assertEqual(self.out, [])

    def test_401_emits_kinit_hint_not_token(self):
        self._post_returns(FakeResp(status=401, body=b''))
        self.b._roundtrip('{"jsonrpc":"2.0","id":5,"method":"tools/call"}', 5, 'tools/call')
        self.assertEqual(len(self.out), 1)
        err = json.loads(self.out[0])
        self.assertEqual(err['id'], 5)
        self.assertRegex(err['error']['message'], r'klist|kinit')
        self.assertNotIn('Negotiate', err['error']['message'])

    def test_200_json_forwarded(self):
        self._post_returns(FakeResp(status=200, body=b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}'))
        self.b._roundtrip('{"jsonrpc":"2.0","id":1,"method":"initialize"}', 1, 'initialize')
        self.assertEqual(len(self.out), 1)
        self.assertIn('2025-06-18', self.out[0])


class Teardown(unittest.TestCase):
    def test_close_sends_delete_with_session(self):
        b = mod.Bridge('https://mcp.x.internal/')
        b.session_id = 'SID-9'
        created = []
        b._connect = lambda: created.append(FakeConn(FakeResp(status=200))) or created[-1]
        b.close()
        self.assertEqual(created[-1].requests[0]['method'], 'DELETE')
        self.assertEqual(created[-1].requests[0]['headers']['Mcp-Session-Id'], 'SID-9')

    def test_close_noop_without_session(self):
        b = mod.Bridge('https://mcp.x.internal/')
        b._connect = lambda: (_ for _ in ()).throw(AssertionError('must not connect'))
        b.close()   # no session -> returns immediately, no connect




class NeverDelegates(unittest.TestCase):
    """SECURITY.md [CL1]. The bridge must never set GSS_C_DELEG_FLAG.

    Load-bearing since [D1]: forwarding needs FORWARDABLE workstation tickets, and
    forwardable is precisely what lets a client hand the server a TGT rather than a
    narrow evidence credential. A server holding a TGT can reach anything that user
    could reach, allowlist or not. This test is what keeps our own client on the
    right side of that, so treat a failure here as a security regression rather
    than a stale assertion to update."""

    def test_init_flags_exclude_delegation(self):
        mod = load_bridge()
        flags = getattr(mod, '_INIT_FLAGS', None)
        self.assertIsNotNone(flags, 'the bridge no longer names its GSS init flags; '
                                    'delegation can no longer be checked here')
        names = {str(getattr(f, 'name', f)) for f in flags}
        self.assertNotIn('delegate_to_peer', names)
        self.assertFalse({n for n in names if 'deleg' in n.lower()},
                         'bridge requests delegation: %r' % (names,))

    def test_the_context_it_builds_requests_no_delegation(self):
        # Belt and braces on the flags list: assert what actually reaches gssapi,
        # so a flag added at the call site rather than in _INIT_FLAGS is caught.
        mod = load_bridge()
        mod.negotiate_header('mcp.example.internal')
        self.assertTrue(fake_gssapi.contexts, 'no initiate context was built')
        used = {str(getattr(f, 'name', f)) for f in (fake_gssapi.contexts[-1].flags or [])}
        self.assertFalse({n for n in used if 'deleg' in n.lower()},
                         'the initiated context requests delegation: %r' % (used,))


if __name__ == '__main__':
    unittest.main()
