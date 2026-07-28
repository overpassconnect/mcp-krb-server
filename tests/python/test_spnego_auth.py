"""Unit tests for server/spnego_auth.py (the Kerberos acceptor). Hermetic - a fake
gssapi stands in, so no KDC is needed. Run: python -m unittest (from tests/python)."""
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
import spnego_auth as A                              # noqa: E402

SPN = 'HTTP@mcp.example.internal'
ALICE = 'alice@EXAMPLE.INTERNAL'


def hdr(principal, prefix='GOOD:'):
    return 'Negotiate ' + base64.b64encode((prefix + principal).encode()).decode()


class SpnegoAuth(unittest.TestCase):
    def setUp(self):
        self.creds = A.make_acceptor_creds(SPN)

    def test_requires_explicit_spn(self):            # [C2]
        with self.assertRaises(ValueError):
            A.make_acceptor_creds('nohostpart')

    def test_valid_token_returns_principal(self):
        p, r = A.authenticate(self.creds, hdr(ALICE))
        self.assertEqual(p, ALICE)

    def test_service_principal_with_instance_ok(self):   # [C3]
        p, _ = A.authenticate(self.creds, hdr('host/host1.example.internal@EXAMPLE.INTERNAL'))
        self.assertTrue(p.startswith('host/host1'))

    def test_incomplete_context_rejected(self):      # [C1] the core
        with self.assertRaises(A.AuthError) as c:
            A.authenticate(self.creds, 'Negotiate ' + base64.b64encode(b'INCOMPLETE').decode())
        self.assertEqual(c.exception.reason, 'context-incomplete')

    def test_non_krb5_mech_rejected(self):           # [C1] mech pin
        with self.assertRaises(A.AuthError) as c:
            A.authenticate(self.creds, hdr(ALICE, 'BADMECH:'))
        self.assertEqual(c.exception.reason, 'non-krb5-mech')

    def test_ntlm_token_rejected_before_crypto(self):  # [C1]
        with self.assertRaises(A.AuthError) as c:
            A.authenticate(self.creds, 'Negotiate TlRMTVNTUAABc29tZQ==')
        self.assertEqual(c.exception.reason, 'ntlm-token-rejected')

    def test_no_header(self):
        with self.assertRaises(A.AuthError) as c:
            A.authenticate(self.creds, '')
        self.assertEqual(c.exception.reason, 'no-negotiate-header')

    def test_oversize_token(self):                   # [C6]
        with self.assertRaises(A.AuthError) as c:
            A.authenticate(self.creds, 'Negotiate ' + ('A' * (A.MAX_TOKEN_B64 + 1)))
        self.assertEqual(c.exception.reason, 'token-size')

    def test_bad_base64(self):
        with self.assertRaises(A.AuthError) as c:
            A.authenticate(self.creds, 'Negotiate @@@not-base64@@@')
        self.assertEqual(c.exception.reason, 'bad-base64')

    def test_malformed_principal_rejected(self):     # [C3]
        for bad in ['evil user@REALM', 'a;rm@REALM', 'a@b@c', 'a\tb@REALM']:
            with self.assertRaises(A.AuthError) as c:
                A.authenticate(self.creds, hdr(bad))
            self.assertEqual(c.exception.reason, 'principal-malformed', bad)

    def test_garbage_token_rejected(self):
        with self.assertRaises(A.AuthError) as c:
            A.authenticate(self.creds, 'Negotiate ' + base64.b64encode(b'random-bytes').decode())
        self.assertTrue(c.exception.reason.startswith('gss-error'))


if __name__ == '__main__':
    unittest.main()
