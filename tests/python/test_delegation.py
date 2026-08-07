"""Unit tests for server/delegation.py and the delegation path in spnego_auth.py.

Hermetic: fake_gssapi stands in, so no KDC is needed. The fake models the
behaviour measured against a real KDC (usage='accept' yields no evidence,
usage='both' yields a credential named for the caller, and a target outside the
realm allowlist is refused with KDC_ERR_BADOPTION), so a regression here means
the same regression in production.

Run: python -m unittest (from tests/python).
"""
import base64
import os
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fake_gssapi                                     # noqa: E402
sys.modules['gssapi'] = fake_gssapi
_exc = types.ModuleType('gssapi.exceptions')
_exc.GSSError = fake_gssapi.GSSError
sys.modules['gssapi.exceptions'] = _exc
_raw_misc = types.ModuleType('gssapi.raw.misc')
_raw_misc.GSSError = fake_gssapi.GSSError
sys.modules['gssapi.raw.misc'] = _raw_misc

REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'server'))
import delegation                                      # noqa: E402
import spnego_auth                                     # noqa: E402

SPN = 'HTTP@mcp.example.internal'
KEYTAB = '/etc/mcp-server/krb5.keytab'
ALICE = 'alice@EXAMPLE.INTERNAL'
TARGET = 'HTTP@ci.example.internal'


def hdr(principal):
    return 'Negotiate ' + base64.b64encode(('GOOD:' + principal).encode()).decode()


class Base(unittest.TestCase):
    def setUp(self):
        fake_gssapi.reset()
        self._saved = dict(delegation.TOOL_TARGETS)
        delegation.TOOL_TARGETS.clear()
        os.environ.pop('MCP_DELEGATION', None)

    def tearDown(self):
        delegation.TOOL_TARGETS.clear()
        delegation.TOOL_TARGETS.update(self._saved)
        os.environ.pop('MCP_DELEGATION', None)

    def enable(self):
        os.environ['MCP_DELEGATION'] = '1'

    def evidence_for(self, principal=ALICE, delegating=False):
        """The credential the acceptor ends up holding for one caller.

        delegating=False is our own client ([CL1]): a NARROW evidence credential,
        stamped by MIT with this acceptor's name. delegating=True is a modified
        client that set GSS_C_DELEG_FLAG: their FULL forwarded TGT, with no such
        stamp and no allowlist applying to it."""
        creds = spnego_auth.make_acceptor_creds(SPN, keytab=KEYTAB, delegation=True)
        if delegating:
            fake_gssapi.SecurityContext.flags_from_initiator = (
                fake_gssapi.RequirementFlag.delegate_to_peer,)
            self.addCleanup(setattr, fake_gssapi.SecurityContext,
                            'flags_from_initiator', ())
        _p, _r, ev = spnego_auth.authenticate(creds, hdr(principal), want_evidence=True)
        return ev

    # The principal form of SPN, which is what is_narrow_evidence compares
    # against; mcp_server derives the same value from MCP_SPN and MCP_REALM.
    IMPERSONATOR = SPN.replace('@', '/') + '@EXAMPLE.INTERNAL'


class OffByDefault(Base):
    def test_disabled_without_env(self):
        self.assertFalse(delegation.enabled())

    def test_target_for_denies_when_disabled(self):
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.target_for('t')
        self.assertEqual(c.exception.reason, 'delegation-disabled')

    def test_negotiate_header_denies_when_disabled(self):
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
        with self.assertRaises(delegation.DelegationError):
            delegation.negotiate_header(object(), 't', self.IMPERSONATOR)

    def test_only_explicit_truthy_values_enable(self):
        for v in ('', '0', 'false', 'no', 'off', 'maybe'):
            os.environ['MCP_DELEGATION'] = v
            self.assertFalse(delegation.enabled(), v)
        for v in ('1', 'true', 'YES', 'On'):
            os.environ['MCP_DELEGATION'] = v
            self.assertTrue(delegation.enabled(), v)


class TargetPolicy(Base):
    def test_unlisted_tool_denied(self):
        self.enable()
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.target_for('nope')
        self.assertEqual(c.exception.reason, 'no-target-policy')

    def test_allowed_tool_returns_its_target(self):
        self.enable()
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
        self.assertEqual(delegation.target_for('t'), TARGET)

    def test_ambiguous_target_denied(self):
        # Two targets would mean something has to CHOOSE at request time, and the
        # only inputs available then come from the caller.
        self.enable()
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET, 'HTTP@other.example.internal'})
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.target_for('t')
        self.assertEqual(c.exception.reason, 'ambiguous-target')

    def test_malformed_target_denied(self):
        self.enable()
        for bad in ['no-at-sign', 'HTTP@', '@host', 'HTTP@UPPER.example.internal',
                    'HTTP@host with space', 'HTTP@host;rm']:
            delegation.TOOL_TARGETS['t'] = frozenset({bad})
            with self.assertRaises(delegation.DelegationError, msg=bad) as c:
                delegation.target_for('t')
            self.assertEqual(c.exception.reason, 'invalid-target-spn', bad)

    def test_empty_target_set_denied(self):
        self.enable()
        delegation.TOOL_TARGETS['t'] = frozenset()
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.target_for('t')
        self.assertEqual(c.exception.reason, 'no-target-policy')


class AcceptorEvidence(Base):
    def test_plain_acceptor_yields_no_evidence(self):
        # The [C2] default. This is the measured MIT behaviour, not a stub.
        creds = spnego_auth.make_acceptor_creds(SPN)
        p, _r, ev = spnego_auth.authenticate(creds, hdr(ALICE), want_evidence=True)
        self.assertEqual(p, ALICE)
        self.assertIsNone(ev)

    def test_delegation_acceptor_yields_evidence_named_for_caller(self):
        ev = self.evidence_for(ALICE)
        self.assertIsNotNone(ev)
        self.assertEqual(str(ev.name), ALICE)

    def test_delegation_requires_explicit_keytab(self):
        with self.assertRaises(ValueError):
            spnego_auth.make_acceptor_creds(SPN, delegation=True)

    def test_delegation_creds_use_an_explicit_ccache(self):
        # Without this the service adopts whatever KRB5CCNAME points at, which
        # either kills startup or silently initiates as somebody else.
        creds = spnego_auth.make_acceptor_creds(SPN, keytab=KEYTAB, delegation=True)
        self.assertEqual(creds.usage, 'both')
        self.assertIn('ccache', creds.store)
        self.assertIn('client_keytab', creds.store)

    def test_two_arg_return_shape_unchanged(self):
        # Existing callers must not break: without want_evidence it is a 2-tuple.
        creds = spnego_auth.make_acceptor_creds(SPN)
        self.assertEqual(len(spnego_auth.authenticate(creds, hdr(ALICE))), 2)

    def test_incomplete_context_yields_no_evidence(self):
        creds = spnego_auth.make_acceptor_creds(SPN, keytab=KEYTAB, delegation=True)
        with self.assertRaises(spnego_auth.AuthError):
            spnego_auth.authenticate(
                creds, 'Negotiate ' + base64.b64encode(b'INCOMPLETE').decode(),
                want_evidence=True)


class Forwarding(Base):
    def test_allowlisted_target_produces_negotiate_header(self):
        self.enable()
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
        fake_gssapi.allow_target(TARGET)
        h = delegation.negotiate_header(self.evidence_for(), 't', self.IMPERSONATOR)
        self.assertTrue(h.startswith('Negotiate '))
        base64.b64decode(h.split(' ', 1)[1], validate=True)   # well-formed

    def test_target_not_allowed_by_kdc_is_refused(self):
        # The realm's target allowlist is enforced by the KDC, so this fails even
        # though the tool policy names the target. Both gates hold independently,
        # and the KDC one is meaningful again now that a forwarded TGT (the
        # credential it does NOT constrain) is refused outright.
        self.enable()
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
        # deliberately do NOT call allow_target
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.negotiate_header(self.evidence_for(), 't', self.IMPERSONATOR)
        self.assertIn('badoption', c.exception.reason)

    def test_missing_evidence_never_falls_back_to_service_identity(self):
        self.enable()
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
        fake_gssapi.allow_target(TARGET)
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.negotiate_header(None, 't', self.IMPERSONATOR)
        self.assertEqual(c.exception.reason, 'no-evidence-credential')

    def test_audit_records_subject_and_target(self):
        self.enable()
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
        fake_gssapi.allow_target(TARGET)
        seen = []
        delegation.negotiate_header(self.evidence_for(ALICE), 't', self.IMPERSONATOR,
                                    audit=seen.append)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]['subject'], ALICE)
        self.assertEqual(seen[0]['target'], TARGET)
        self.assertEqual(seen[0]['outcome'], 'allow')

    def test_no_audit_event_on_refusal(self):
        # A refused forward must not leave an 'allow' record behind.
        self.enable()
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
        seen = []
        with self.assertRaises(delegation.DelegationError):
            delegation.negotiate_header(self.evidence_for(), 't', self.IMPERSONATOR,
                                        audit=seen.append)
        self.assertEqual(seen, [])


class ShippedPolicyIsEmpty(unittest.TestCase):
    def test_no_targets_are_shipped(self):
        # Shipping a populated allowlist would enable forwarding for anyone who
        # merely sets MCP_DELEGATION, turning a deployment decision into a typo.
        import importlib
        mod = importlib.reload(delegation)
        self.assertEqual(mod.TOOL_TARGETS, {})




class OperatorTargetOverlay(Base):
    """delegation._targets_from_env. This parses MCP_DELEGATION_TARGETS, which is
    now what actually decides where a caller's credential may be sent, so every
    rejection below is load-bearing rather than tidiness."""

    def parse(self, raw):
        return delegation._targets_from_env(raw)

    def test_empty_and_absent_yield_nothing(self):
        for raw in (None, '', '   ', ',,'):
            self.assertEqual({}, self.parse(raw))

    def test_a_well_formed_entry_parses(self):
        self.assertEqual({'trigger_build': frozenset({'HTTP@ci.example.internal'})},
                         self.parse('trigger_build=HTTP@ci.example.internal'))

    def test_several_entries_and_surrounding_space(self):
        got = self.parse(' a=HTTP@one.example.internal , b=ldap@two.example.internal ')
        self.assertEqual({'a': frozenset({'HTTP@one.example.internal'}),
                          'b': frozenset({'ldap@two.example.internal'})}, got)

    def test_malformed_entries_raise(self):
        for raw in ('trigger_build',                      # no '='
                    '=HTTP@ci.example.internal',          # no tool
                    'trigger_build=',                     # no SPN
                    'trigger_build=notanspn',             # no '@'
                    'trigger_build=HTTP@',                # no host
                    'Trigger=HTTP@ci.example.internal',   # tool charset
                    'a b=HTTP@ci.example.internal',       # space in tool
                    'a=HTTP@ci example.internal',         # space in host
                    'a=HTTP@ci.example.internal;x'):      # shell metachar
            with self.subTest(raw=raw):
                self.assertRaises(ValueError, self.parse, raw)

    def test_a_deployment_cannot_redirect_a_reviewed_target(self):
        # The whole point of keeping literals in code is that they were reviewed.
        # Precedence would let site.env quietly point one somewhere else.
        delegation.TOOL_TARGETS['reviewed'] = frozenset({'HTTP@ci.example.internal'})
        try:
            self.assertRaises(ValueError, self.parse, 'reviewed=HTTP@evil.example.internal')
        finally:
            del delegation.TOOL_TARGETS['reviewed']

    def test_duplicate_tool_raises_rather_than_last_wins(self):
        self.assertRaises(ValueError, self.parse,
                          'a=HTTP@one.example.internal,a=HTTP@two.example.internal')

    def test_too_many_entries_raise(self):
        raw = ','.join('t%d=HTTP@h%d.example.internal' % (i, i)
                       for i in range(delegation._MAX_ENV_TARGETS + 1))
        self.assertRaises(ValueError, self.parse, raw)

    def test_one_tool_gets_exactly_one_target(self):
        # target_for() refuses an ambiguous row, so the overlay must never build
        # one; a comma is an entry separator, never a second target.
        got = self.parse('a=HTTP@one.example.internal')
        self.assertEqual(1, len(got['a']))

    def test_shipped_policy_is_empty(self):
        # Guards the merge at import time: with no env set, the repo grants nothing.
        self.assertEqual({}, self.parse(os.environ.get('MCP_DELEGATION_TARGETS')))


class ForwardedTgtIsRefused(Base):
    """SECURITY.md [D1], finding 8. A caller who sets GSS_C_DELEG_FLAG hands the
    acceptor their whole TGT rather than a narrow evidence credential. The realm's
    servicedelegationtarget allowlist does not apply to a TGT, so accepting one
    would let us reach anything that caller could reach. It is refused.

    Why it can be refused reliably: MIT stamps the impersonator field only on the
    accept path taken when the caller did NOT delegate, and stamps it from the
    LOCAL acceptor's own name, so it cannot be forged from the wire. The client's
    one lever picks the branch, and the branch handing us the dangerous credential
    is the branch that loses the stamp."""

    def test_a_delegating_caller_is_refused(self):
        self.enable()
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
        fake_gssapi.allow_target(TARGET)          # the KDC would happily comply
        ev = self.evidence_for(delegating=True)
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.negotiate_header(ev, 't', self.IMPERSONATOR)
        self.assertEqual(c.exception.reason, 'credential-not-narrow-evidence')

    def test_a_non_delegating_caller_still_works(self):
        # Guards against "fix" by refusing everything, which would pass the test
        # above while silently disabling the feature.
        self.enable()
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
        fake_gssapi.allow_target(TARGET)
        h = delegation.negotiate_header(self.evidence_for(), 't', self.IMPERSONATOR)
        self.assertTrue(h.startswith('Negotiate '))

    def test_refusal_leaves_no_allow_audit_record(self):
        self.enable()
        delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
        fake_gssapi.allow_target(TARGET)
        seen = []
        with self.assertRaises(delegation.DelegationError):
            delegation.negotiate_header(self.evidence_for(delegating=True), 't',
                                        self.IMPERSONATOR, audit=seen.append)
        self.assertEqual(seen, [])


class NarrowEvidenceCheck(Base):
    """delegation.is_narrow_evidence in isolation. Every branch fails CLOSED:
    the answer is True only when it has been positively established."""

    def test_true_only_for_our_own_evidence_credential(self):
        self.assertTrue(delegation.is_narrow_evidence(
            self.evidence_for(), self.IMPERSONATOR))

    def test_false_for_a_forwarded_tgt(self):
        self.assertFalse(delegation.is_narrow_evidence(
            self.evidence_for(delegating=True), self.IMPERSONATOR))

    def test_false_for_none(self):
        self.assertFalse(delegation.is_narrow_evidence(None, self.IMPERSONATOR))

    def test_false_when_another_acceptor_composed_it(self):
        # Non-empty is not enough. A credential stamped by some OTHER service is
        # not evidence that anyone authenticated HERE.
        self.assertFalse(delegation.is_narrow_evidence(
            self.evidence_for(), 'HTTP/other.example.internal@EXAMPLE.INTERNAL'))

    def test_false_when_no_expected_impersonator_is_supplied(self):
        for bad in (None, ''):
            self.assertFalse(delegation.is_narrow_evidence(self.evidence_for(), bad))

    def test_false_when_the_platform_cannot_answer(self):
        # An MIT older than 1.16, or a python-gssapi without the raw call. The
        # feature must switch itself off rather than guess.
        saved = fake_gssapi.raw
        fake_gssapi.raw = object()               # no inquire_cred_by_oid
        try:
            self.assertFalse(delegation.is_narrow_evidence(
                self.evidence_for(), self.IMPERSONATOR))
        finally:
            fake_gssapi.raw = saved

    def test_false_when_the_oid_call_raises(self):
        saved = fake_gssapi.raw

        class Boom:
            @staticmethod
            def inquire_cred_by_oid(cred, oid):
                raise fake_gssapi.GSSError('unsupported')

        fake_gssapi.raw = Boom()
        try:
            self.assertFalse(delegation.is_narrow_evidence(
                self.evidence_for(), self.IMPERSONATOR))
        finally:
            fake_gssapi.raw = saved


class SpnegoFraming(unittest.TestCase):
    """The header must carry a SPNEGO token, not a bare krb5 AP-REQ.

    This is asserted directly because the difference is invisible from a working
    deployment: Go's gokrb5 accepts a bare AP-REQ, so a site whose only
    downstream is Gitea cannot tell. A Java acceptor holding a SPNEGO-only
    acceptor credential refuses it with

        GSSException: No credential found for: 1.2.840.113554.1.2.2 usage: Accept

    which surfaces as an HTTP 500 and reads like a fault in the far end rather
    than a mech mismatch here.
    """

    KRB5 = '1.2.840.113554.1.2.2'
    SPNEGO = '1.3.6.1.5.5.2'

    def test_der_oid_matches_the_known_encodings(self):
        # Derived rather than hardcoded in the source, so pin the two answers.
        self.assertEqual(delegation._der_oid(self.SPNEGO),
                         bytes.fromhex('06062b0601050502'))
        self.assertEqual(delegation._der_oid(self.KRB5),
                         bytes.fromhex('06092a864886f712010202'))

    def test_wrap_is_an_application_0_spnego_token_carrying_the_ap_req(self):
        w = delegation._spnego_wrap(b'\xaa\xbb\xcc', self.KRB5, self.SPNEGO)
        # 60 22            [APPLICATION 0], 34 bytes
        #   06 06 2b...02    SPNEGO
        #   a0 18            [0] NegotiationToken
        #     30 16          NegTokenInit
        #       a0 0d 30 0b 06 09 2a...02   mechTypes: krb5 alone
        #       a2 05 04 03 aabbcc          mechToken: the AP-REQ
        self.assertEqual(
            w.hex(),
            '602206062b0601050502a0183016a00d300b06092a864886f712010202a2050403aabbcc')

    def test_long_form_length_for_a_realistic_token(self):
        # A real AP-REQ is well over 127 bytes, so the short-form length encoding
        # is never exercised in production and must not be the only one tested.
        w = delegation._spnego_wrap(b'A' * 300, self.KRB5, self.SPNEGO)
        self.assertEqual(w[0], 0x60)
        self.assertEqual(w[1], 0x82)                    # long form, 2 length bytes
        self.assertIn(bytes.fromhex('0482012c'), w)     # OCTET STRING, 300 bytes

    def test_header_produced_by_negotiate_header_is_framed(self):
        d = Base('run')
        d.setUp()
        try:
            d.enable()
            delegation.TOOL_TARGETS['t'] = frozenset({TARGET})
            fake_gssapi.allow_target(TARGET)
            h = delegation.negotiate_header(d.evidence_for(), 't', d.IMPERSONATOR)
            tok = base64.b64decode(h.split(' ', 1)[1], validate=True)
            self.assertEqual(tok[0], 0x60, 'not an [APPLICATION 0] GSS token')
            self.assertIn(bytes.fromhex('06062b0601050502'), tok[:16],
                          'SPNEGO mech OID missing: this is a bare AP-REQ')
            self.assertIn(bytes.fromhex('06092a864886f712010202'), tok,
                          'krb5 not offered in mechTypes')
        finally:
            d.tearDown()


if __name__ == '__main__':
    unittest.main()
