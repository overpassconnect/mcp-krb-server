"""The MCP_SITE_TOOLS extension point and authz.register_tool_policy.

Covers the contract a deployment relies on: unset means nothing changes, a
broken path fails loudly rather than serving a half-registered tool set, and a
registered site policy survives a policy-overlay reload (which rebuilds the live
map from the reviewed defaults and would otherwise drop it).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'server'))
sys.path.insert(0, os.path.dirname(__file__))
import fake_gssapi  # noqa: F401  installs the fake gssapi module

import authz


class RegisterToolPolicy(unittest.TestCase):
    def setUp(self):
        self._live = dict(authz.TOOL_GROUPS)
        self._default = dict(authz._DEFAULT_TOOL_GROUPS)

    def tearDown(self):
        authz.TOOL_GROUPS = self._live
        authz._DEFAULT_TOOL_GROUPS.clear()
        authz._DEFAULT_TOOL_GROUPS.update(self._default)

    def test_registers_in_both_maps(self):
        authz.register_tool_policy('site_tool', {'site-group'})
        self.assertEqual(authz.TOOL_GROUPS['site_tool'], frozenset({'site-group'}))
        self.assertEqual(authz._DEFAULT_TOOL_GROUPS['site_tool'], frozenset({'site-group'}))

    def test_survives_a_policy_overlay_reload(self):
        # _apply() rebuilds the live map from the reviewed defaults. A site entry
        # written only to the live map would be lost here, and the tool would
        # start denying with no visible cause.
        authz.register_tool_policy('site_tool', {'site-group'})
        authz.reset_policy()
        self.assertIn('site_tool', authz.TOOL_GROUPS)

    def test_any_authenticated_is_accepted(self):
        authz.register_tool_policy('open_tool', authz.ANY_AUTHENTICATED)
        self.assertIs(authz.TOOL_GROUPS['open_tool'], authz.ANY_AUTHENTICATED)

    def test_authorization_actually_applies_to_a_site_tool(self):
        authz.register_tool_policy('site_tool', {'site-group'})
        authz.ipa_groups = lambda p: {'site-group'}
        self.assertEqual(authz.authorize_tool('u@R', 'site_tool')[0], True)
        authz.ipa_groups = lambda p: {'other'}
        self.assertEqual(authz.authorize_tool('u@R', 'site_tool')[0], False)

    def test_rejects_junk(self):
        for tool, groups in (('bad name', {'g'}), ('ok', set()), ('ok', {'bad group'}),
                             (None, {'g'}), ('ok', {''})):
            with self.assertRaises(ValueError):
                authz.register_tool_policy(tool, groups)


class SiteToolsLoader(unittest.TestCase):
    """_load_site_tools is exercised by source inspection: importing mcp_server
    needs the MCP SDK, which the hermetic suite deliberately does not have."""

    def setUp(self):
        p = os.path.join(os.path.dirname(__file__), '..', '..', 'server', 'mcp_server.py')
        with open(p, encoding='utf-8') as f:
            self.src = f.read()

    def test_unset_is_a_no_op(self):
        self.assertIn("os.environ.get('MCP_SITE_TOOLS', '').strip()", self.src)
        self.assertIn('if not path:\n        return', self.src)

    def test_fails_loudly_on_a_bad_path(self):
        self.assertIn('raise RuntimeError', self.src)
        self.assertIn('is not a loadable Python file', self.src)

    def test_requires_a_register_callable(self):
        self.assertIn("register = getattr(module, 'register', None)", self.src)
        self.assertIn('if not callable(register):', self.src)

    def test_loads_before_the_app_is_built(self):
        # FastMCP collects tools at decoration time, so the site file has to run
        # before streamable_http_app() or its tools are missing from the served
        # tool list.
        self.assertLess(self.src.index('_load_site_tools()'),
                        self.src.index('mcp.streamable_http_app()'))

    def test_hands_the_policy_registrar_to_the_site_file(self):
        self.assertIn('register(mcp, require, forward_header, authz.register_tool_policy)',
                      self.src)

    def test_load_is_audited(self):
        self.assertIn("'event': 'site_tools.loaded'", self.src)


class SiteToolsEndToEnd(unittest.TestCase):
    """Drive the loader's logic over a real temp file, without the MCP SDK."""

    def test_a_site_file_registers_a_tool_and_its_policy(self):
        src = (
            'def register(mcp, require, forward_header, register_tool_policy):\n'
            '    @mcp.tool()\n'
            '    def demo(ctx):\n'
            '        return require(ctx, "demo")\n'
            '    register_tool_policy("demo", {"demo-group"})\n'
        )
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False,
                                         encoding='utf-8') as fh:
            fh.write(src)
            path = fh.name
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location('site_probe', path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            seen = []

            class FakeMcp:
                def tool(self):
                    def deco(fn):
                        seen.append(fn.__name__)
                        return fn
                    return deco

            mod.register(FakeMcp(), lambda *a: 'p', lambda *a: 'h',
                         authz.register_tool_policy)
            self.assertEqual(seen, ['demo'])
            self.assertEqual(authz.TOOL_GROUPS['demo'], frozenset({'demo-group'}))
        finally:
            os.unlink(path)
            authz.TOOL_GROUPS.pop('demo', None)
            authz._DEFAULT_TOOL_GROUPS.pop('demo', None)


if __name__ == '__main__':
    unittest.main()
