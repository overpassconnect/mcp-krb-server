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
import authz
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
        self._saved = dict(authz.TOOL_TARGETS)
        authz.TOOL_TARGETS.clear()
        os.environ.pop('MCP_DELEGATION', None)

    def tearDown(self):
        authz.TOOL_TARGETS.clear()
        authz.TOOL_TARGETS.update(self._saved)
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
        authz.TOOL_TARGETS['t'] = frozenset({TARGET})
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.target_for('t')
        self.assertEqual(c.exception.reason, 'delegation-disabled')

    def test_negotiate_header_denies_when_disabled(self):
        authz.TOOL_TARGETS['t'] = frozenset({TARGET})
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
        authz.TOOL_TARGETS['t'] = frozenset({TARGET})
        self.assertEqual(delegation.target_for('t'), TARGET)

    def test_ambiguous_target_denied(self):
        # Two targets would mean something has to CHOOSE at request time, and the
        # only inputs available then come from the caller.
        self.enable()
        authz.TOOL_TARGETS['t'] = frozenset({TARGET, 'HTTP@other.example.internal'})
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.target_for('t')
        self.assertEqual(c.exception.reason, 'ambiguous-target')

    def test_malformed_target_denied(self):
        self.enable()
        for bad in ['no-at-sign', 'HTTP@', '@host', 'HTTP@UPPER.example.internal',
                    'HTTP@host with space', 'HTTP@host;rm']:
            authz.TOOL_TARGETS['t'] = frozenset({bad})
            with self.assertRaises(delegation.DelegationError, msg=bad) as c:
                delegation.target_for('t')
            self.assertEqual(c.exception.reason, 'invalid-target-spn', bad)

    def test_empty_target_set_denied(self):
        self.enable()
        authz.TOOL_TARGETS['t'] = frozenset()
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
        authz.TOOL_TARGETS['t'] = frozenset({TARGET})
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
        authz.TOOL_TARGETS['t'] = frozenset({TARGET})
        # deliberately do NOT call allow_target
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.negotiate_header(self.evidence_for(), 't', self.IMPERSONATOR)
        self.assertIn('badoption', c.exception.reason)

    def test_missing_evidence_never_falls_back_to_service_identity(self):
        self.enable()
        authz.TOOL_TARGETS['t'] = frozenset({TARGET})
        fake_gssapi.allow_target(TARGET)
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.negotiate_header(None, 't', self.IMPERSONATOR)
        self.assertEqual(c.exception.reason, 'no-evidence-credential')

    def test_audit_records_subject_and_target(self):
        self.enable()
        authz.TOOL_TARGETS['t'] = frozenset({TARGET})
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
        authz.TOOL_TARGETS['t'] = frozenset({TARGET})
        seen = []
        with self.assertRaises(delegation.DelegationError):
            delegation.negotiate_header(self.evidence_for(), 't', self.IMPERSONATOR,
                                        audit=seen.append)
        self.assertEqual(seen, [])


class ShippedPolicyIsEmpty(unittest.TestCase):
    def test_no_targets_are_shipped(self):
        # Shipping a populated allowlist would enable forwarding for anyone who
        # merely sets MCP_DELEGATION, turning a deployment decision into a typo.
        #
        # The map moved to authz, which owns the policy document it now comes
        # from, so this reloads authz rather than delegation.
        import importlib
        mod = importlib.reload(authz)
        self.assertEqual(mod._DEFAULT_TOOL_TARGETS, {})
        self.assertEqual(mod.TOOL_TARGETS, {})




class TargetsFromPolicy(Base):
    """authz.targets_from_json. This decides where a caller's credential may be
    sent, so every rejection below is load-bearing rather than tidiness.

    It replaced delegation._targets_from_env, which parsed the same information
    out of MCP_DELEGATION_TARGETS. The targets now live in the policy document
    beside the groups, so both halves of a tool's authorization have one home,
    one lifetime and one reader. Two of the old tests do not survive the move and
    should not be re-added: duplicate keys and an entry cap were properties of a
    comma-separated string, and JSON has neither problem."""

    def parse(self, doc):
        return authz.targets_from_json(doc, known_tools={'a', 'b', 'trigger_build',
                                                         'reviewed'})

    def test_empty_and_absent_yield_nothing(self):
        self.assertEqual({}, self.parse({}))
        self.assertEqual({}, self.parse({'a': {'groups': ['g']}}))
        self.assertEqual({}, self.parse({'a': {'groups': ['g'], 'forwards_to': None}}))

    def test_a_well_formed_entry_parses(self):
        self.assertEqual(
            {'trigger_build': frozenset({'HTTP@ci.example.internal'})},
            self.parse({'trigger_build': {'groups': ['g'],
                                          'forwards_to': 'HTTP@ci.example.internal'}}))

    def test_several_entries(self):
        got = self.parse({'a': {'groups': ['g'], 'forwards_to': 'HTTP@one.example.internal'},
                          'b': {'groups': ['g'], 'forwards_to': 'ldap@two.example.internal'}})
        self.assertEqual({'a': frozenset({'HTTP@one.example.internal'}),
                          'b': frozenset({'ldap@two.example.internal'})}, got)

    def test_malformed_targets_raise(self):
        for spn in ('notanspn',                    # no '@'
                    'HTTP@',                       # no host
                    '@ci.example.internal',        # no service
                    'HTTP@ci example.internal',    # space in host
                    'HTTP@ci.example.internal;x',  # shell metachar
                    'HTTP@CI.EXAMPLE.INTERNAL',    # host charset is lowercase
                    '', 5, [], {}):
            with self.subTest(spn=spn):
                self.assertRaises(ValueError, self.parse,
                                  {'a': {'groups': ['g'], 'forwards_to': spn}})

    def test_an_unknown_tool_is_refused(self):
        self.assertRaises(ValueError, self.parse,
                          {'nope': {'groups': ['g'],
                                    'forwards_to': 'HTTP@ci.example.internal'}})

    def test_an_unknown_key_is_refused(self):
        # Silently ignoring a key is how a typo becomes a tool with no target.
        self.assertRaises(ValueError, authz.policy_from_json,
                          {'whoami': {'groups': authz.ANY_TOKEN, 'forwards': 'x'}})

    def test_a_document_cannot_redirect_a_reviewed_target(self):
        # The point of keeping literals in code is that they were reviewed.
        # Precedence would let a document quietly point one somewhere else.
        authz._DEFAULT_TOOL_TARGETS['reviewed'] = frozenset({'HTTP@ci.example.internal'})
        try:
            self.assertRaises(ValueError, self.parse,
                              {'reviewed': {'groups': ['g'],
                                            'forwards_to': 'HTTP@evil.example.internal'}})
        finally:
            del authz._DEFAULT_TOOL_TARGETS['reviewed']

    def test_one_tool_gets_exactly_one_target(self):
        # target_for() refuses an ambiguous row, so the document must never build
        # one. A single string is the only shape accepted.
        got = self.parse({'a': {'groups': ['g'], 'forwards_to': 'HTTP@one.example.internal'}})
        self.assertEqual(1, len(got['a']))

    def test_shipped_policy_grants_nothing(self):
        # With no document loaded, the repo forwards nowhere.
        self.assertEqual({}, authz._DEFAULT_TOOL_TARGETS)


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
        authz.TOOL_TARGETS['t'] = frozenset({TARGET})
        fake_gssapi.allow_target(TARGET)          # the KDC would happily comply
        ev = self.evidence_for(delegating=True)
        with self.assertRaises(delegation.DelegationError) as c:
            delegation.negotiate_header(ev, 't', self.IMPERSONATOR)
        self.assertEqual(c.exception.reason, 'credential-not-narrow-evidence')

    def test_a_non_delegating_caller_still_works(self):
        # Guards against "fix" by refusing everything, which would pass the test
        # above while silently disabling the feature.
        self.enable()
        authz.TOOL_TARGETS['t'] = frozenset({TARGET})
        fake_gssapi.allow_target(TARGET)
        h = delegation.negotiate_header(self.evidence_for(), 't', self.IMPERSONATOR)
        self.assertTrue(h.startswith('Negotiate '))

    def test_refusal_leaves_no_allow_audit_record(self):
        self.enable()
        authz.TOOL_TARGETS['t'] = frozenset({TARGET})
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


class NarrowEvidenceAdversarial(Base):
    """Attacks on is_narrow_evidence, whose failure is the one that is not
    contained. Everywhere else a mistake denies something that should work. Here,
    a single wrong True means a modified client's forwarded TGT is treated as our
    own evidence credential, and the delegation allowlist stops meaning anything:
    the caller reaches whatever their own ticket reaches.

    The invariant asserted below is NOT "returns False". It is **never returns
    True**. On a platform that answers nonsense, raising is an acceptable
    outcome, because the exception denies the forward. Quietly answering yes is
    not. So a shape that crashes passes these tests and a shape that says True
    fails them.

    What these tests cannot establish: that MIT never populates the impersonator
    field from anything that arrived over the wire. That is a property of
    kg_compose_deleg_cred() in C, and it was settled by measurement against a
    live KDC rather than here. These tests cover everything on this side of that
    boundary.
    """

    def _returns(self, payload):
        """Force inquire_cred_by_oid to return `payload`, whatever its shape."""
        saved = fake_gssapi.raw

        class Fixed:
            @staticmethod
            def inquire_cred_by_oid(cred, oid):
                return payload

        fake_gssapi.raw = Fixed()
        self.addCleanup(setattr, fake_gssapi, 'raw', saved)

    def _never_true(self, payload, why):
        self._returns(payload)
        try:
            got = delegation.is_narrow_evidence(self.evidence_for(), self.IMPERSONATOR)
        except Exception:
            return          # denied by raising, which is fail-closed
        self.assertFalse(got, why)

    # --- the battery is only meaningful if the genuine case still passes ------

    def test_control_the_real_credential_is_still_accepted(self):
        self.assertTrue(delegation.is_narrow_evidence(
            self.evidence_for(), self.IMPERSONATOR),
            'the attack battery would be vacuous if nothing is ever accepted')

    # --- malformed return shapes ---------------------------------------------

    def test_no_buffers(self):
        self._never_true([], 'an empty answer is not a positive one')

    def test_two_buffers_even_when_one_matches(self):
        want = self.IMPERSONATOR.encode()
        self._never_true([want, want], 'exactly one buffer is the contract')

    def test_buffer_that_is_text_rather_than_bytes(self):
        self._never_true([self.IMPERSONATOR], 'str has no decode; must not pass')

    def test_buffer_that_is_not_valid_utf8(self):
        self._never_true([b'\xff\xfe\x00'], 'undecodable bytes must not pass')

    def test_return_value_with_no_length(self):
        self._never_true(object(), 'a shapeless answer must not pass')

    def test_return_value_is_none(self):
        self._never_true(None, 'no answer at all must not pass')

    # --- near misses on the name. This is the actual security property: the
    # --- comparison is equality against OUR spn, not a prefix, substring or
    # --- case-folded match.

    def test_near_miss_names_are_all_refused(self):
        base = self.IMPERSONATOR
        for name, why in (
            (base + '\x00',            'a trailing NUL must not compare equal'),
            (base + '\n',              'trailing whitespace must not compare equal'),
            (base + ' ',               'trailing space must not compare equal'),
            (base + 'X',               'a longer name must not pass a prefix check'),
            (base[:-1],                'a shorter name must not pass a prefix check'),
            (base.lower(),             'case must matter: krb5 names are case sensitive'),
            (base.split('@')[0],       'the service part alone must not pass a substring check'),
            ('@' + base.split('@')[1], 'the realm alone must not pass a substring check'),
            ('HTTP/evil.example.internal@' + base.split('@')[1],
                                       'another service in our own realm must not pass'),
        ):
            with self.subTest(name=name):
                self._never_true([name.encode()], why)

    def test_our_own_name_from_a_different_realm_is_refused(self):
        svc = self.IMPERSONATOR.split('@')[0]
        self._never_true([(svc + '@OTHER.INTERNAL').encode()],
                         'same service, foreign realm, is a different principal')


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
            authz.TOOL_TARGETS['t'] = frozenset({TARGET})
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
