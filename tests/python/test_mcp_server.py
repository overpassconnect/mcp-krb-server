"""SDK integration smoke test for server/mcp_server.py. Skips if the `mcp` SDK is
not installed. Hermetic Kerberos (fake gssapi); drives the FastMCP app under
uvicorn. Run: python -m unittest (from tests/python)."""
import base64
import json
import http.client
import os
import sys
import threading
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fake_gssapi                                   # noqa: E402
sys.modules['gssapi'] = fake_gssapi
_exc = types.ModuleType('gssapi.exceptions')
_exc.GSSError = fake_gssapi.GSSError
sys.modules['gssapi.exceptions'] = _exc

try:
    import mcp            # noqa: F401
    import uvicorn        # noqa: F401
    HAVE_SDK = True
except Exception:
    HAVE_SDK = False

PORT = 8921
os.environ['MCP_SPN'] = 'HTTP@mcp.example.internal'
os.environ['MCP_LISTEN'] = '127.0.0.1:%d' % PORT
os.environ['KRB5_KTNAME'] = '/nonexistent-in-test'
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'server'))

ALICE = 'alice@EXAMPLE.INTERNAL'
INIT = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
        'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
                   'clientInfo': {'name': 't', 'version': '0'}}}


def tok(principal):
    return 'Negotiate ' + base64.b64encode(('GOOD:' + principal).encode()).decode()


@unittest.skipUnless(HAVE_SDK, 'mcp SDK / uvicorn not installed')
class SdkSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import mcp_server
        cfg = uvicorn.Config(mcp_server.app, host='127.0.0.1', port=PORT, log_level='error')
        cls.server = uvicorn.Server(cfg)
        cls.server.install_signal_handlers = lambda: None
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        for _ in range(100):
            if getattr(cls.server, 'started', False):
                break
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True

    def _post(self, body, auth=None):
        c = http.client.HTTPConnection('127.0.0.1', PORT)
        h = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
        if auth:
            h['Authorization'] = auth
        c.request('POST', '/', json.dumps(body), h)
        r = c.getresponse()
        b = r.read().decode()
        c.close()
        return r.status, b

    def test_no_auth_401(self):                       # middleware works end-to-end
        s, _ = self._post(INIT)
        self.assertEqual(s, 401)

    def test_ntlm_401(self):
        s, b = self._post(INIT, 'Negotiate TlRMTVNTUAABxx')
        self.assertEqual(s, 401)
        self.assertNotIn('ntlm', b.lower())

    def test_authenticated_initialize(self):
        s, b = self._post(INIT, tok(ALICE))
        self.assertEqual(s, 200)
        self.assertIn('mcp-krb-server', b)              # serverInfo.name flows through

    def test_privileged_tool_denied(self):            # [S2] DENY path end-to-end through the SDK
        # ALICE is in no groups in this hermetic env (nss lookup fails closed).
        call = {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                'params': {'name': 'restart_service', 'arguments': {'name': 'nginx'}}}
        s, b = self._post(call, tok(ALICE))
        self.assertEqual(s, 200)
        self.assertIn('not authorized', b)

    def test_privileged_tool_allowed_for_group_member(self):   # [S2] ALLOW path end-to-end
        # Put ALICE in mcp-operators via the (monkeypatched) IPA group lookup and
        # confirm the privileged tool now runs. Restored in finally so no other
        # test sees the patched membership.
        import mcp_server
        orig = mcp_server.authz.ipa_groups
        mcp_server.authz.ipa_groups = lambda p: {'mcp-operators'} if p == ALICE else set()
        try:
            call = {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call',
                    'params': {'name': 'restart_service', 'arguments': {'name': 'nginx'}}}
            s, b = self._post(call, tok(ALICE))
            self.assertEqual(s, 200)
            self.assertIn('would restart nginx', b)
            self.assertNotIn('not authorized', b)
        finally:
            mcp_server.authz.ipa_groups = orig

    def test_tool_call_sees_principal(self):
        # stateless mode: probe whether tools/call works and the tool sees the
        # per-request principal from the ASGI scope.
        call = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                'params': {'name': 'whoami', 'arguments': {}}}
        s, b = self._post(call, tok(ALICE))
        self.assertEqual(s, 200, 'tool call HTTP status')
        self.assertIn(ALICE, b, 'whoami must return the authenticated principal; body=%s' % b[:300])


if __name__ == '__main__':
    unittest.main()
