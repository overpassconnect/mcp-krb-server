"""The acceptor credential has to outlive its own TGT.

This is a regression test for a live outage, and the shape of that outage is
the reason the tests below assert what they do.

With delegation on, the acceptor credential is acquired usage='both', so it
holds initiator material: an ordinary TGT with an ordinary 24 hour life. The
server acquired it once at startup and held the object. MIT will re-acquire
from the client keytab, but only at acquisition time, so nothing ever
refreshed it and it expired in place after a day.

What made it invisible for nine days is the asymmetry. Accepting an incoming
ticket reads the keytab, which never expires, so authentication and
authorization kept succeeding and the audit log kept recording allowed calls.
Only the delegated leg failed, refused by the KDC with KDC_ERR_BADOPTION,
which reads as a delegation policy fault and sends you to inspect FreeIPA
rather than the server. Every rule there was correct the whole time.

So the tests here are not "does it refresh". They are:
  * an expired credential is never handed out (the outage itself),
  * a keytab-derived acceptor credential is not re-acquired on every request
    (the obvious over-correction, which would hammer the KDC),
  * inquiring an expired credential raises rather than reporting zero, which
    is why the check cannot be a plain numeric comparison.
"""
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fake_gssapi                                            # noqa: E402
sys.modules['gssapi'] = fake_gssapi
_exc = types.ModuleType('gssapi.exceptions')
_exc.GSSError = fake_gssapi.GSSError
sys.modules['gssapi.exceptions'] = _exc

import spnego_auth                                            # noqa: E402

SPN = 'HTTP@mcp.example.internal'
KEYTAB = '/etc/mcp-server/krb5.keytab'


class Base(unittest.TestCase):
    def setUp(self):
        fake_gssapi.reset()


class ExpiredCredentialsAreReplaced(Base):

    def test_a_fresh_credential_is_reused_rather_than_reacquired(self):
        c = spnego_auth.RenewingAcceptorCredentials(SPN, keytab=KEYTAB, delegation=True)
        before = len(fake_gssapi.acquisitions)
        first = c.get()
        for _ in range(20):
            self.assertIs(first, c.get())
        self.assertEqual(before, len(fake_gssapi.acquisitions),
                         "re-acquired a credential that had a full day left; that is a "
                         "KDC request on every single inbound call")

    def test_an_expired_credential_is_never_handed_out(self):
        c = spnego_auth.RenewingAcceptorCredentials(SPN, keytab=KEYTAB, delegation=True)
        spent = c.get()
        spent.expire()                       # nine days of uptime, compressed
        fresh = c.get()
        self.assertIsNot(fresh, spent,
                         "handed out the expired credential: this is the outage, where "
                         "the server keeps accepting callers and every delegated call "
                         "is refused by the KDC")
        self.assertEqual(fake_gssapi.Credentials.INITIATE_LIFETIME, fresh.lifetime)

    def test_a_credential_inside_the_margin_is_replaced_before_it_expires(self):
        # Expiring mid-request is the same outage with worse timing, so the
        # replacement has to happen while the old one still technically works.
        c = spnego_auth.RenewingAcceptorCredentials(SPN, keytab=KEYTAB, delegation=True)
        old = c.get()
        old._lifetime = spnego_auth.CREDENTIAL_REFRESH_MARGIN - 1
        self.assertIsNot(old, c.get())

    def test_replacement_survives_repeated_expiry(self):
        # A long-lived process expires its credential many times over. Once was
        # never the problem; the problem was zero.
        c = spnego_auth.RenewingAcceptorCredentials(SPN, keytab=KEYTAB, delegation=True)
        seen = []
        for _ in range(5):
            cred = c.get()
            seen.append(id(cred))
            cred.expire()
        self.assertEqual(5, len(set(seen)), "some expired credential was reused")


class ReceiveOnlyCredentialsAreLeftAlone(Base):

    def test_keytab_derived_acceptor_creds_are_not_churned(self):
        # usage='accept' comes from a keytab and has no expiry. Re-acquiring it
        # per request would be the over-correction: pointless load, and load on
        # the KDC specifically.
        c = spnego_auth.RenewingAcceptorCredentials(SPN, delegation=False)
        before = len(fake_gssapi.acquisitions)
        for _ in range(20):
            c.get()
        self.assertEqual(before, len(fake_gssapi.acquisitions))

    def test_indefinite_lifetime_does_not_read_as_expiring(self):
        self.assertFalse(spnego_auth.credential_expiring(
            fake_gssapi.Credentials(usage='accept')))


class ExpiryDetection(Base):

    def test_an_expired_credential_raises_rather_than_reporting_zero(self):
        # The reason credential_expiring cannot be a plain numeric comparison.
        cred = fake_gssapi.Credentials(usage='both')
        cred.expire()
        with self.assertRaises(fake_gssapi.GSSError):
            cred.lifetime
        self.assertTrue(spnego_auth.credential_expiring(cred))

    def test_none_counts_as_expiring(self):
        self.assertTrue(spnego_auth.credential_expiring(None))


class StartupStillFailsFast(Base):

    def test_construction_acquires_immediately(self):
        # The direct make_acceptor_creds call failed at startup on a bad SPN or
        # an unreadable keytab. Deferring acquisition to the first request would
        # move that failure into serving, where it reads as an auth bug.
        before = len(fake_gssapi.acquisitions)
        spnego_auth.RenewingAcceptorCredentials(SPN, keytab=KEYTAB, delegation=True)
        self.assertEqual(before + 1, len(fake_gssapi.acquisitions))

    def test_a_bad_spn_still_raises_at_construction(self):
        with self.assertRaises(ValueError):
            spnego_auth.RenewingAcceptorCredentials('nohostpart')

    def test_delegation_without_a_keytab_still_raises_at_construction(self):
        with self.assertRaises(ValueError):
            spnego_auth.RenewingAcceptorCredentials(SPN, delegation=True)


if __name__ == "__main__":
    unittest.main()
