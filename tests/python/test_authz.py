"""Unit tests for server/authz.py - the SECURITY-OWNED per-tool IPA-group policy
and the SSSD group lookup. Pure and hermetic: no MCP SDK, no KDC, no real nss
(the group lookup is monkeypatched), so this file runs everywhere python3 does
and is the standalone home of the authorization ALLOW/DENY matrix [S2].
Run: python -m unittest (from tests/python)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'server'))

import authz                                            # noqa: E402

ALICE = 'alice@EXAMPLE.INTERNAL'
BOB = 'bob@EXAMPLE.INTERNAL'


class AuthorizeConnection(unittest.TestCase):
    """The coarse connection gate (before any tool runs)."""

    def test_realm_allowed(self):
        self.assertTrue(authz.authorize_connection(ALICE))

    def test_wrong_realm_denied(self):
        self.assertFalse(authz.authorize_connection('eve@EVIL.EXAMPLE'))

    def test_non_string_denied(self):
        # None (unauthenticated) and bytes must never slip through endswith().
        self.assertFalse(authz.authorize_connection(None))
        self.assertFalse(authz.authorize_connection(b'alice@EXAMPLE.INTERNAL'))

    def test_lookalike_realm_not_spoofable(self):
        # ends with the realm STRING but not with '@REALM' - must be denied.
        self.assertFalse(authz.authorize_connection('eve@evil-EXAMPLE.INTERNAL'))
        self.assertFalse(authz.authorize_connection('alice@EXAMPLE.INTERNAL.evil.example'))


class AuthorizeTool(unittest.TestCase):
    """The ALLOW/DENY matrix. ipa_groups() is monkeypatched so the decision logic
    is tested independently of nss/SSSD."""

    def setUp(self):
        self._orig = authz.ipa_groups

    def tearDown(self):
        authz.ipa_groups = self._orig

    def _groups(self, mapping):
        authz.ipa_groups = lambda principal: set(mapping.get(principal, set()))

    def test_any_authenticated_allows_with_no_groups(self):
        self._groups({})                                # principal in zero groups
        allowed, detail = authz.authorize_tool(ALICE, 'whoami')
        self.assertTrue(allowed)
        self.assertEqual(detail, 'any-authenticated')

    def test_group_required_allow_when_member(self):    # [S2] ALLOW path
        self._groups({ALICE: {'mcp-operators'}})
        allowed, detail = authz.authorize_tool(ALICE, 'restart_service')
        self.assertTrue(allowed)
        self.assertEqual(detail, ['mcp-operators'])     # matched groups reported for audit

    def test_group_required_deny_when_not_member(self):
        self._groups({ALICE: {'mcp-users'}})            # has mcp-users, not mcp-operators
        allowed, detail = authz.authorize_tool(ALICE, 'restart_service')
        self.assertFalse(allowed)
        self.assertEqual(detail, 'no-group')

    def test_list_projects_needs_mcp_users(self):
        self._groups({ALICE: {'mcp-users'}, BOB: set()})
        self.assertTrue(authz.authorize_tool(ALICE, 'list_projects')[0])
        self.assertFalse(authz.authorize_tool(BOB, 'list_projects')[0])

    def test_unknown_tool_denied(self):                 # deny-by-default
        self._groups({ALICE: {'mcp-operators', 'mcp-users'}})
        allowed, detail = authz.authorize_tool(ALICE, 'no_such_tool')
        self.assertFalse(allowed)
        self.assertEqual(detail, 'no-policy')

    def test_union_semantics_any_of_the_groups(self):
        # a tool requiring ANY of several groups: membership in one suffices.
        authz.TOOL_GROUPS['_probe'] = {'g1', 'g2'}
        try:
            self._groups({ALICE: {'g2'}})
            allowed, detail = authz.authorize_tool(ALICE, '_probe')
            self.assertTrue(allowed)
            self.assertEqual(detail, ['g2'])
        finally:
            del authz.TOOL_GROUPS['_probe']

    def test_extra_groups_are_ignored(self):
        # membership in unrelated groups must not grant a tool it does not require.
        self._groups({ALICE: {'mcp-users', 'wheel', 'admins'}})
        self.assertFalse(authz.authorize_tool(ALICE, 'restart_service')[0])


class IpaGroupsLookup(unittest.TestCase):
    """The nss/SSSD lookup boundary: strict input, fail-closed, local-part only."""

    def test_bad_username_returns_empty_without_touching_nss(self):
        called = {'hit': False}
        orig = authz._nss_groups

        def tripwire(user):
            called['hit'] = True
            return {'g'}

        authz._nss_groups = tripwire
        try:
            self.assertEqual(authz.ipa_groups('bad user!@EXAMPLE.INTERNAL'), set())
            self.assertFalse(called['hit'])             # junk never reaches nss
        finally:
            authz._nss_groups = orig

    def test_nss_error_fails_closed(self):
        orig = authz._nss_groups

        def boom(user):
            raise OSError('sssd unavailable')

        authz._nss_groups = boom
        try:
            self.assertEqual(authz.ipa_groups(ALICE), set())    # error => deny, not crash
        finally:
            authz._nss_groups = orig

    def test_lookup_uses_local_part_only(self):
        seen = {}
        orig = authz._nss_groups

        def capture(user):
            seen['user'] = user
            return {'g'}

        authz._nss_groups = capture
        try:
            authz.ipa_groups('alice@EXAMPLE.INTERNAL')
            self.assertEqual(seen['user'], 'alice')     # realm stripped before lookup
        finally:
            authz._nss_groups = orig


if __name__ == '__main__':
    unittest.main()
