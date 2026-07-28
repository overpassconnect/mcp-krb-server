"""Unit tests for server/spnego_asgi.py (the self-contained SPNEGO ASGI auth
middleware). Hermetic - fake gssapi + a stub inner ASGI app, no SDK, no KDC.
Run: python -m unittest (from tests/python)."""
import asyncio
import base64
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fake_gssapi                                   # noqa: E402
sys.modules['gssapi'] = fake_gssapi
_exc = types.ModuleType('gssapi.exceptions')
_exc.GSSError = fake_gssapi.GSSError
sys.modules['gssapi.exceptions'] = _exc
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'server'))
from spnego_asgi import SpnegoAuthMiddleware, SCOPE_PRINCIPAL   # noqa: E402

SPN = 'HTTP@mcp.example.internal'
REALM = '@EXAMPLE.INTERNAL'


def tok(principal, prefix='GOOD:'):
    return 'Negotiate ' + base64.b64encode((prefix + principal).encode()).decode()


def build(authorize=None):
    return SpnegoAuthMiddleware(app=None, spn=SPN,
                                authorize=authorize or (lambda p: p.endswith(REALM)),
                                audit=lambda e: None)


async def _drive(mw, headers, scope_type='http'):
    scope = {'type': scope_type, 'method': 'POST', 'path': '/mcp', 'client': ('10.0.0.9', 5),
             'headers': [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
    seen = {'called': False, 'principal': '__unset__'}

    async def inner(s, r, sd):
        seen['called'] = True
        seen['principal'] = s.get(SCOPE_PRINCIPAL)
    mw.app = inner
    sent = []

    async def send(m):
        sent.append(m)

    async def receive():
        return {'type': 'http.request', 'body': b''}
    await mw(scope, receive, send)
    return seen, sent


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class Middleware(unittest.TestCase):
    def test_no_auth_401_with_challenge(self):
        seen, sent = run(_drive(build(), {}))
        self.assertFalse(seen['called'])
        self.assertEqual(sent[0]['status'], 401)
        self.assertIn((b'www-authenticate', b'Negotiate'), sent[0]['headers'])

    def test_401_body_generic(self):                 # [C4]
        seen, sent = run(_drive(build(), {'authorization': tok('alice' + REALM, 'BADMECH:')}))
        body = sent[1]['body']
        self.assertNotIn(b'mech', body.lower())
        self.assertIn(b'authentication required', body)

    def test_valid_sets_scope_and_calls_app(self):
        seen, sent = run(_drive(build(), {'authorization': tok('alice' + REALM)}))
        self.assertTrue(seen['called'])
        self.assertEqual(seen['principal'], 'alice' + REALM)

    def test_ntlm_401(self):                          # [C1]
        seen, sent = run(_drive(build(), {'authorization': 'Negotiate TlRMTVNTUAABxx'}))
        self.assertFalse(seen['called'])
        self.assertEqual(sent[0]['status'], 401)

    def test_incomplete_context_401(self):            # [C1]
        hdr = 'Negotiate ' + base64.b64encode(b'INCOMPLETE').decode()
        seen, sent = run(_drive(build(), {'authorization': hdr}))
        self.assertFalse(seen['called'])
        self.assertEqual(sent[0]['status'], 401)

    def test_authorize_false_403(self):
        seen, sent = run(_drive(build(authorize=lambda p: False), {'authorization': tok('mallory' + REALM)}))
        self.assertFalse(seen['called'])
        self.assertEqual(sent[0]['status'], 403)
        self.assertNotIn(b'mallory', sent[1]['body'])   # [C4] principal not reflected

    def test_lifespan_passthrough(self):              # must not touch non-http scopes
        seen, sent = run(_drive(build(), {}, scope_type='lifespan'))
        self.assertTrue(seen['called'])               # inner app ran, no auth attempted
        self.assertEqual(sent, [])

    def test_requires_authorize_callable(self):
        with self.assertRaises(ValueError):
            SpnegoAuthMiddleware(app=None, spn=SPN, authorize=None)


if __name__ == '__main__':
    unittest.main()
