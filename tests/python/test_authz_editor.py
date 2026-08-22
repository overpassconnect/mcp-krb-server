"""Tests for the OPTIONAL, disabled-by-default authz policy editor
(server/authz_editor.py) and the runtime policy-overlay layer in server/authz.py.

Hermetic: no MCP SDK, no KDC, no browser. The editor is an ASGI app, driven here
by a tiny in-process ASGI harness with the caller principal pre-stamped on the
scope (as SpnegoAuthMiddleware would). Covers the disabled-by-default gate, the
policy-admin allowlist, the ambient-credential CSRF defenses, method/precondition
semantics, schema validation + fail-safe, and merge-over-defaults.
Run: python -m unittest (from tests/python)."""
import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'server'))

import authz            # noqa: E402
import authz_editor     # noqa: E402

ALICE = 'alice@EXAMPLE.INTERNAL'
BOB = 'bob@EXAMPLE.INTERNAL'
ORIGIN = 'https://mcp.example.internal'
KNOWN = frozenset(authz._DEFAULT_TOOL_GROUPS)


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _call(app, method, path, principal=ALICE, headers=None, body=b''):
    hdr_list = [(k.lower().encode('latin-1'), v.encode('latin-1')) for k, v in (headers or {}).items()]
    scope = {'type': 'http', 'method': method, 'path': path, 'headers': hdr_list,
             'client': ('127.0.0.1', 33333), authz_editor.SCOPE_PRINCIPAL: principal}
    sent = []
    state = {'sent_body': False}

    async def receive():
        if not state['sent_body']:
            state['sent_body'] = True
            return {'type': 'http.request', 'body': body, 'more_body': False}
        return {'type': 'http.disconnect'}

    async def send(msg):
        sent.append(msg)

    await app(scope, receive, send)
    start = next(m for m in sent if m['type'] == 'http.response.start')
    out = b''.join(m.get('body', b'') for m in sent if m['type'] == 'http.response.body')
    resp_headers = {k.decode('latin-1').lower(): v.decode('latin-1') for k, v in start['headers']}
    return start['status'], resp_headers, out


class BuildEditorGate(unittest.TestCase):
    """Disabled by default; enabling requires a valid policy-admin allowlist."""

    _ENV = ('MCP_AUTHZ_EDITOR', 'MCP_POLICY_ADMINS', 'MCP_POLICY_FILE', 'MCP_PUBLIC_ORIGIN')

    def setUp(self):
        self._save_env = {k: os.environ.get(k) for k in self._ENV}
        for k in self._ENV:
            os.environ.pop(k, None)
        self._save_pol = authz.TOOL_GROUPS

    def tearDown(self):
        for k, v in self._save_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        authz.TOOL_GROUPS = self._save_pol

    def test_disabled_when_unset(self):
        self.assertIsNone(authz_editor.build_editor(lambda e: None))

    def test_disabled_when_flag_on_but_no_admins(self):
        os.environ['MCP_AUTHZ_EDITOR'] = '1'
        events = []
        self.assertIsNone(authz_editor.build_editor(events.append))
        self.assertTrue(any(e.get('reason') == 'no-valid-policy-admins' for e in events))

    def test_invalid_admins_are_dropped_and_stay_disabled(self):
        os.environ['MCP_AUTHZ_EDITOR'] = '1'
        os.environ['MCP_POLICY_ADMINS'] = 'not-a-principal, eve@EVIL.EXAMPLE'
        self.assertIsNone(authz_editor.build_editor(lambda e: None))

    def test_enabled_with_valid_admin(self):
        os.environ['MCP_AUTHZ_EDITOR'] = '1'
        os.environ['MCP_POLICY_ADMINS'] = ALICE + ' , ' + BOB
        os.environ['MCP_POLICY_FILE'] = os.path.join(tempfile.mkdtemp(), 'missing.json')
        ed = authz_editor.build_editor(lambda e: None)
        self.assertIsNotNone(ed)
        self.assertEqual(ed.admins, frozenset({ALICE, BOB}))


class EditorApp(unittest.TestCase):
    def setUp(self):
        self._save_pol = authz.TOOL_GROUPS
        authz.reset_policy()
        self.tmp = tempfile.mkdtemp()
        self.policy_file = os.path.join(self.tmp, 'tool-groups.json')
        self.audits = []
        self.app = authz_editor.AuthzEditorApp(self.policy_file, ORIGIN, frozenset({ALICE}),
                                               self.audits.append, KNOWN)

    def tearDown(self):
        authz.TOOL_GROUPS = self._save_pol
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _put(self, obj, principal=ALICE, origin=ORIGIN, sfs='same-origin',
             ctype='application/json', ifmatch='{{CURRENT}}', raw=None):
        if ifmatch == '{{CURRENT}}':
            ifmatch = authz.policy_etag()
        headers = {}
        if origin is not None:
            headers['origin'] = origin
        if sfs is not None:
            headers['sec-fetch-site'] = sfs
        if ctype is not None:
            headers['content-type'] = ctype
        if ifmatch is not None:
            headers['if-match'] = ifmatch
        body = raw if raw is not None else json.dumps(obj).encode()
        return run(_call(self.app, 'PUT', authz_editor.PATH_API, principal=principal,
                         headers=headers, body=body))

    # --- access control ----------------------------------------------------
    def test_non_admin_denied_view(self):
        s, _, _ = run(_call(self.app, 'GET', authz_editor.PATH_HTML, principal=BOB))
        self.assertEqual(s, 403)

    def test_unauthenticated_denied(self):
        s, _, _ = run(_call(self.app, 'GET', authz_editor.PATH_API, principal=None))
        self.assertEqual(s, 403)

    def test_admin_gets_html_with_nonce_csp(self):
        s, h, body = run(_call(self.app, 'GET', authz_editor.PATH_HTML))
        self.assertEqual(s, 200)
        self.assertIn('text/html', h['content-type'])
        self.assertIn('nonce-', h['content-security-policy'])
        self.assertIn("default-src 'none'", h['content-security-policy'])
        self.assertIn(b'Per-tool authorization', body)
        self.assertIn(ALICE.encode(), body)                 # principal shown, escaped

    def test_admin_gets_policy_json_with_etag(self):
        s, h, body = run(_call(self.app, 'GET', authz_editor.PATH_API))
        self.assertEqual(s, 200)
        self.assertEqual(h.get('etag'), authz.policy_etag())
        d = json.loads(body)
        self.assertEqual(d['policy']['whoami'], {'groups': authz.ANY_TOKEN})
        self.assertIn('restart_service', d['tools'])

    def test_the_api_reports_the_registered_tools(self):
        # The sidebar is only as good as this list.
        s, _, body = run(_call(self.app, 'GET', authz_editor.PATH_API))
        self.assertEqual(s, 200)
        tools = json.loads(body)['tools']
        self.assertIn('restart_service', tools)
        self.assertEqual(sorted(tools), sorted(set(tools)))

    # --- happy-path write --------------------------------------------------
    def test_valid_put_updates_policy_and_persists(self):
        s, h, body = self._put({'list_projects': {'groups': ['mcp-users', 'mcp-leads']}})
        self.assertEqual(s, 200, body)
        self.assertEqual(sorted(authz.TOOL_GROUPS['list_projects']), ['mcp-leads', 'mcp-users'])
        self.assertTrue(os.path.exists(self.policy_file))
        self.assertEqual(json.loads(body)['etag'], authz.policy_etag())
        self.assertTrue(any(e.get('event') == 'policy.change' for e in self.audits))

    def test_put_any_token_opens_tool(self):
        s, _, _ = self._put({'restart_service': {'groups': authz.ANY_TOKEN}})
        self.assertEqual(s, 200)
        allowed, detail = authz.authorize_tool(BOB, 'restart_service')
        self.assertTrue(allowed)
        self.assertEqual(detail, 'any-authenticated')

    def test_omitted_tools_keep_code_default(self):
        self._put({'list_projects': ['mcp-users']})
        # whoami + restart_service were not in the overlay: still the defaults.
        self.assertIs(authz.TOOL_GROUPS['whoami'], authz.ANY_AUTHENTICATED)
        self.assertEqual(set(authz.TOOL_GROUPS['restart_service']), {'mcp-operators'})

    # --- CSRF defenses -----------------------------------------------------
    def test_put_missing_origin_rejected(self):
        s, _, _ = self._put({'list_projects': ['mcp-users']}, origin=None)
        self.assertEqual(s, 403)

    def test_put_foreign_origin_rejected(self):
        s, _, _ = self._put({'list_projects': ['mcp-users']}, origin='https://evil.example')
        self.assertEqual(s, 403)

    def test_put_cross_site_sec_fetch_rejected(self):
        s, _, _ = self._put({'list_projects': ['mcp-users']}, sfs='cross-site')
        self.assertEqual(s, 403)

    def test_put_non_json_content_type_rejected(self):
        s, _, _ = self._put({'list_projects': ['mcp-users']}, ctype='text/plain')
        self.assertEqual(s, 415)

    # --- preconditions -----------------------------------------------------
    def test_put_without_if_match_rejected(self):
        s, _, _ = self._put({'list_projects': ['mcp-users']}, ifmatch=None)
        self.assertEqual(s, 428)

    def test_put_stale_if_match_conflicts(self):
        s, h, _ = self._put({'list_projects': ['mcp-users']}, ifmatch='"stale"')
        self.assertEqual(s, 412)
        self.assertEqual(h.get('etag'), authz.policy_etag())

    def test_wrong_method_405(self):
        s, h, _ = run(_call(self.app, 'DELETE', authz_editor.PATH_API))
        self.assertEqual(s, 405)
        self.assertEqual(h.get('allow'), 'GET, PUT')

    def test_unknown_admin_path_404(self):
        s, _, _ = run(_call(self.app, 'GET', '/admin/nope'))
        self.assertEqual(s, 404)

    # --- validation + fail-safe -------------------------------------------
    def test_put_body_too_large_rejected(self):
        s, _, _ = self._put(None, raw=b' ' * (authz_editor._MAX_BODY + 10))
        self.assertEqual(s, 413)

    def test_put_invalid_json_rejected(self):
        s, _, _ = self._put(None, raw=b'{not json')
        self.assertEqual(s, 400)

    def test_put_unknown_tool_rejected_and_policy_unchanged(self):
        before = authz.policy_to_json()
        s, _, _ = self._put({'rm_rf_slash': ['mcp-operators']})
        self.assertEqual(s, 400)
        self.assertEqual(authz.policy_to_json(), before)
        self.assertFalse(os.path.exists(self.policy_file))   # nothing persisted

    def test_put_bad_group_name_rejected(self):
        before = authz.policy_to_json()
        s, _, _ = self._put({'list_projects': {'groups': ['bad group!']}})
        self.assertEqual(s, 400)
        self.assertEqual(authz.policy_to_json(), before)

    def test_editor_gate_independent_of_policy(self):
        # A successful policy edit cannot change who is a policy-admin: the
        # allowlist lives in the app, never in the editable TOOL_GROUPS.
        s, _, _ = self._put({'restart_service': {'groups': authz.ANY_TOKEN}})
        self.assertEqual(s, 200)
        self.assertEqual(self.app.admins, frozenset({ALICE}))
        s, _, _ = run(_call(self.app, 'GET', authz_editor.PATH_HTML, principal=BOB))
        self.assertEqual(s, 403)


class DispatchRouting(unittest.TestCase):
    """Only /admin/* http requests reach the editor; everything else (and every
    non-http scope: lifespan/websocket) must reach the wrapped MCP app so its
    session-manager lifespan starts."""

    def test_routing(self):
        calls = {'inner': [], 'editor': []}

        async def inner(scope, r, s):
            calls['inner'].append(scope.get('type') + ':' + scope.get('path', ''))

        async def editor(scope, r, s):
            calls['editor'].append(scope.get('path', ''))

        async def noop():
            return {}

        async def nosend(m):
            pass

        d = authz_editor.Dispatch(inner, editor)
        run(d({'type': 'http', 'path': '/admin/authz'}, noop, nosend))    # -> editor
        run(d({'type': 'http', 'path': '/'}, noop, nosend))               # -> inner (MCP)
        run(d({'type': 'lifespan', 'path': ''}, noop, nosend))            # -> inner (critical)
        run(d({'type': 'websocket', 'path': '/admin/x'}, noop, nosend))   # non-http -> inner
        self.assertEqual(calls['editor'], ['/admin/authz'])
        self.assertEqual(calls['inner'], ['http:/', 'lifespan:', 'websocket:/admin/x'])


class PolicyPersistence(unittest.TestCase):
    """The authz.py runtime-overlay layer, exercised directly."""

    def setUp(self):
        self._save_pol = authz.TOOL_GROUPS
        authz.reset_policy()
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, 'p.json')

    def tearDown(self):
        authz.TOOL_GROUPS = self._save_pol
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_to_from_json_roundtrip(self):
        j = authz.policy_to_json()
        self.assertEqual(j['whoami'], {'groups': authz.ANY_TOKEN})
        back = authz.policy_from_json(j)
        self.assertIs(back['whoami'], authz.ANY_AUTHENTICATED)
        self.assertEqual(set(back['restart_service']), {'mcp-operators'})

    def test_a_bare_group_list_is_refused_as_the_old_format(self):
        # No fallback on purpose. Accepting both shapes would mean a file could
        # be half-migrated and still load, which is how the two halves of a
        # policy drift apart again.
        with self.assertRaises(ValueError) as e:
            authz.policy_from_json({'whoami': authz.ANY_TOKEN})
        self.assertIn('migrate-policy.py', str(e.exception))

    def test_forwards_to_round_trips(self):
        j = {'list_projects': {'groups': ['mcp-users'],
                               'forwards_to': 'HTTP@ci.example.internal'}}
        self.assertEqual({'list_projects': frozenset({'HTTP@ci.example.internal'})},
                         authz.targets_from_json(j, known_tools=KNOWN))

    def test_from_json_rejects_unknown_tool(self):
        with self.assertRaises(ValueError):
            authz.policy_from_json({'nope': {'groups': ['mcp-users']}})

    def test_from_json_rejects_bad_shapes(self):
        for bad in ([], {'list_projects': {'groups': []}},
                     {'list_projects': {'groups': 'mcp-users'}},
                     {'list_projects': {'groups': ['ok', 5]}},
                     {'list_projects': {'groups': ['bad!name']}},
                     {'list_projects': ['mcp-users']}):        # the old bare-list shape
            with self.assertRaises(ValueError):
                authz.policy_from_json(bad)

    def test_write_policy_persists_and_merges_over_defaults(self):
        etag = authz.write_policy(self.path, {'list_projects': {'groups': ['mcp-users', 'mcp-leads']}}, known_tools=KNOWN)
        self.assertTrue(os.path.exists(self.path))
        self.assertEqual(etag, authz.policy_etag())
        self.assertEqual(set(authz.TOOL_GROUPS['list_projects']), {'mcp-users', 'mcp-leads'})
        self.assertIs(authz.TOOL_GROUPS['whoami'], authz.ANY_AUTHENTICATED)  # default kept

    def test_write_policy_invalid_does_not_touch_disk_or_live(self):
        before = authz.policy_to_json()
        with self.assertRaises(ValueError):
            authz.write_policy(self.path, {'unknown_tool': {'groups': ['g']}}, known_tools=KNOWN)
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(authz.policy_to_json(), before)

    def test_load_missing_file_is_defaults(self):
        ok, reason = authz.load_policy_file(self.path, known_tools=KNOWN)
        self.assertTrue(ok)
        self.assertEqual(authz.policy_to_json(), authz.policy_to_json(authz._DEFAULT_TOOL_GROUPS))

    def test_load_corrupt_file_fails_closed(self):
        authz.write_policy(self.path, {'list_projects': {'groups': ['mcp-users']}}, known_tools=KNOWN)
        good = authz.policy_to_json()
        with open(self.path, 'w', encoding='utf-8') as f:
            f.write('{ this is not json')
        ok, reason = authz.load_policy_file(self.path, known_tools=KNOWN)
        self.assertFalse(ok)
        self.assertTrue(reason.startswith('invalid'))
        self.assertEqual(authz.policy_to_json(), good)       # kept last-good, not opened

    def test_reset_reverts_to_default(self):
        authz.write_policy(self.path, {'restart_service': {'groups': authz.ANY_TOKEN}}, known_tools=KNOWN)
        authz.reset_policy()
        self.assertEqual(set(authz.TOOL_GROUPS['restart_service']), {'mcp-operators'})

    def test_etag_changes_with_policy(self):
        e0 = authz.policy_etag()
        authz.write_policy(self.path, {'list_projects': {'groups': ['mcp-users', 'x-team']}}, known_tools=KNOWN)
        self.assertNotEqual(e0, authz.policy_etag())


class PageTemplate(unittest.TestCase):
    """Properties of the served HTML that only a browser would otherwise catch.

    The page is a Python string containing JavaScript, which is a quiet trap:
    Python consumes backslash escapes before the browser ever sees them, and
    the result is still a valid Python module. Nothing fails until the page is
    loaded.
    """

    def test_the_template_stays_a_raw_string(self):
        src = authz_editor._HTML
        # Two characters, backslash then n, inside a JS string literal.
        self.assertIn(r'split("\n")', src)
        # A real newline there would be a JS syntax error.
        self.assertNotIn('split("' + chr(10) + '")', src)
        # The token regex needs a doubled backslash; a single one is a
        # different, wrong pattern that happens to still compile.
        self.assertIn(r'[^"\\]', src)
        self.assertIn(r'(\s*:)', src)

    def test_the_two_layers_exist(self):
        src = authz_editor._HTML
        for needed in ('id="hl"', 'id="policy"', 'class="editor"', 'wrap="off"'):
            self.assertIn(needed, src)
        # White-space handling and wrapping must be identical in both layers or
        # the caret drifts away from the glyphs it is sitting on.
        self.assertIn('white-space: pre;', src)

    def test_every_write_to_the_textarea_repaints(self):
        # The highlighted layer is a copy. A write that does not repaint leaves
        # the two showing different text, which looks like corruption.
        src = authz_editor._HTML
        writes = [i for i in range(len(src)) if src.startswith('ta.value = ', i)]
        self.assertGreaterEqual(len(writes), 2)
        for i in writes:
            following = src[i:i + 260]
            self.assertIn('refresh();', following,
                          'a write to ta.value is not followed by refresh()')

    def test_both_json_error_dialects_are_parsed(self):
        # V8 reports "at position 42"; SpiderMonkey reports "at line 3 column
        # 27". Handling one engine means the caret silently fails to move in
        # the other, which is how this shipped working only in Chrome.
        src = authz_editor._HTML
        self.assertIn(r'/position (\d+)/', src)
        self.assertIn(r'/line (\d+) column (\d+)/', src)

    def test_the_sidebar_scans_rather_than_parses(self):
        # Half-typed JSON does not parse, and that is precisely when a tool
        # name is being entered, so a parse-based sidebar would freeze at the
        # moment it is most useful.
        src = authz_editor._HTML
        self.assertIn('function namedInText', src)
        scan = src[src.index('function namedInText'):src.index('function li(')]
        self.assertIn('KEY.exec', scan)
        self.assertNotIn('JSON.parse', scan)

    def test_the_sidebar_is_fed_by_the_api_tool_list(self):
        # The registered set must come from the server, not a copy in the page
        # that would drift the moment a tool is added.
        src = authz_editor._HTML
        self.assertIn('TOOLS = (d.tools || [])', src)
        self.assertIn('id="t-on"', src)
        self.assertIn('id="t-off"', src)
        self.assertIn('id="t-bad"', src)

    def test_save_is_disabled_while_the_json_is_invalid(self):
        src = authz_editor._HTML
        self.assertIn('saveBtn.disabled = !check(false);', src)
        # A failed load leaves an empty box; Save must not be live over it.
        self.assertIn('saveBtn.disabled = true;', src)

    def test_the_page_carries_no_external_asset(self):
        # default-src 'none' would block them anyway; this catches the mistake
        # at review time rather than as a blank page.
        src = authz_editor._HTML
        for scheme in ('http://', 'https://', '//cdn', 'integrity='):
            self.assertNotIn(scheme, src)


if __name__ == '__main__':
    unittest.main()
