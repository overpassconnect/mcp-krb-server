"""Unit tests for mcp-krb-bridge.py (the stdio bridge client). Traceability in
../../SECURITY.md, section "The test suite".
Run:  python -m unittest -v  (from tests/python)"""
import base64
import importlib.util
import json
import os
import sys
import types
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


# DER encodings, tag and length included.
KRB5_OID_DER = bytes.fromhex('06092a864886f712010202')       # 1.2.840.113554.1.2.2
SPNEGO_OID_DER = bytes.fromhex('06062b0601050502')           # 1.3.6.1.5.5.2
NTLM_OID = bytes.fromhex('2b06010401823702020a')             # 1.3.6.1.4.1.311.2.2.10, body
# What server/spnego_auth.py [C1] screens the base64 header for.
C1_NTLM_MARKERS = ('TlRMTVNTU', 'KwYBBAGCNwIC')


def tlv(buf, at=0):
    """One DER element at `at`: (tag, value, offset just past it)."""
    tag, n, at = buf[at], buf[at + 1], at + 2
    if n & 0x80:
        k = n & 0x7F
        n, at = int.from_bytes(buf[at:at + k], 'big'), at + k
    return tag, buf[at:at + n], at + n


def load_bridge_with_pyspnego(fake_spnego):
    """The Windows branch: no python-gssapi, pyspnego present."""
    saved = {k: sys.modules.get(k) for k in ('gssapi', 'spnego')}
    os.environ.pop('MCP_KRB_NOAUTH', None)
    sys.modules['gssapi'] = None                 # makes `import gssapi` raise ImportError
    sys.modules['spnego'] = fake_spnego
    try:
        spec = importlib.util.spec_from_file_location('mcp_krb_bridge_sspi', BRIDGE)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


class AsksForKerberosOnly(unittest.TestCase):
    """SECURITY.md [CL2]. The bridge asks for krb5 by name and never offers NTLM,
    whatever credentials the workstation holds.

    Asked for SPNEGO, the GSS library offers every mech the user has credentials
    for. On a Mac that held NTLM credentials from an SMB share mounted in Finder,
    every token listed NTLMSSP and the server refused all of them ([C1],
    'ntlm-token-rejected'). The fake models that workstation, so these tests fail
    against the old SPNEGO request."""

    def setUp(self):
        self.mod = load_bridge()
        fake_gssapi.WORKSTATION_MECHS.append(fake_gssapi._NTLM)   # the SMB mount

    def tearDown(self):
        fake_gssapi.reset()

    def token(self, header):
        self.assertTrue(header.startswith('Negotiate '))
        return base64.b64decode(header.split(' ', 1)[1], validate=True)

    def test_the_context_it_builds_asks_for_krb5(self):
        self.mod.negotiate_header('mcp.example.internal')
        self.assertTrue(fake_gssapi.contexts, 'no initiate context was built')
        self.assertEqual(fake_gssapi.contexts[-1].requested_mech,
                         fake_gssapi.OID('1.2.840.113554.1.2.2'),
                         'the bridge no longer asks for the krb5 mech by name')

    def test_no_ntlm_in_the_token_while_the_workstation_holds_ntlm(self):
        header = self.mod.negotiate_header('mcp.example.internal')
        tok = self.token(header)
        self.assertNotIn(NTLM_OID, tok)
        self.assertNotIn(b'NTLMSSP', tok)
        for marker in C1_NTLM_MARKERS:
            self.assertNotIn(marker, header, 'the server would refuse this header')

    def test_the_model_reproduces_the_failure(self):
        # Without this, the test above could pass because the fake never offers
        # NTLM at all. Built the way the bridge used to build it, the same
        # workstation's token names NTLM. (Whether the server's base64 screen
        # also matches depends on where the OID falls in the token, byte 45 on
        # the real Mac, so the DER bytes are what is asserted.)
        ctx = fake_gssapi.SecurityContext(
            name=fake_gssapi.Name('HTTP@mcp.example.internal', 'hostbased_service'),
            usage='initiate', mech=fake_gssapi.OID('1.3.6.1.5.5.2'),
            flags=self.mod._INIT_FLAGS)
        self.assertIn(NTLM_OID, ctx.step())

    def test_the_header_is_spnego_offering_krb5_alone(self):
        # Framed as SPNEGO because a Java acceptor holding a SPNEGO-only
        # credential (Jenkins) answers a bare krb5 token with HTTP 500.
        tok = self.token(self.mod.negotiate_header('mcp.example.internal'))
        tag, body, end = tlv(tok)
        self.assertEqual((tag, end), (0x60, len(tok)))
        self.assertTrue(body.startswith(SPNEGO_OID_DER))
        tag, neg, _ = tlv(body, len(SPNEGO_OID_DER))
        self.assertEqual(tag, 0xA0)                          # negTokenInit
        tag, seq, _ = tlv(neg)
        self.assertEqual(tag, 0x30)
        tag, mech_types, at = tlv(seq)
        self.assertEqual(tag, 0xA0)
        self.assertEqual(tlv(mech_types)[:2], (0x30, KRB5_OID_DER), 'mech list is not krb5 alone')
        tag, mech_token, _ = tlv(seq, at)
        self.assertEqual(tag, 0xA2)
        tag, inner, _ = tlv(mech_token)
        self.assertEqual(tag, 0x04)
        self.assertEqual(inner[0], 0x60)
        self.assertEqual(tlv(inner)[1][:len(KRB5_OID_DER)], KRB5_OID_DER,
                         'the mechToken is not a krb5 token')

    def test_a_token_that_is_not_krb5_is_refused(self):
        spnego_from_gss = fake_gssapi.SecurityContext(
            name=fake_gssapi.Name('HTTP@mcp.example.internal', 'hostbased_service'),
            usage='initiate', mech=fake_gssapi.OID('1.3.6.1.5.5.2')).step()
        for bad in (spnego_from_gss, b'NTLMSSP\x00\x01\x00\x00\x00', b'', b'\x60'):
            with self.assertRaises(RuntimeError):
                self.mod.spnego_krb5_only(bad)

    def test_windows_path_asks_pyspnego_for_kerberos(self):
        calls = []

        class Ctx:
            def step(self):
                return fake_gssapi._krb5_token(b'FAKE-SSPI-AP-REQ')

        fake_spnego = types.ModuleType('spnego')
        fake_spnego.client = lambda **kw: calls.append(kw) or Ctx()
        m = load_bridge_with_pyspnego(fake_spnego)
        tok = self.token(m.negotiate_header('mcp.example.internal'))
        self.assertEqual(calls, [{'hostname': 'mcp.example.internal', 'service': 'HTTP',
                                  'protocol': 'kerberos'}])
        self.assertNotIn(NTLM_OID, tok)
        self.assertTrue(tlv(tok)[1].startswith(SPNEGO_OID_DER))


if __name__ == '__main__':
    unittest.main()
