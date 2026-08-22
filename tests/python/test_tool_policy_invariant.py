"""Machine-enforces SECURITY.md deployment-checklist item 12: every @mcp.tool in
server/mcp_server.py must call require() with ITS OWN name as the first statement,
and must have an entry in the security-owned policy (authz._DEFAULT_TOOL_GROUPS).

Why this is an AST test and not an import test: importing mcp_server pulls in
mcp.server.fastmcp, which is a pip-only dependency absent from most boxes. An
import-based test would skip exactly where the invariant is least likely to be
checked by a human, reproducing the non-enforcement this file exists to fix. So we
parse the source instead and import only authz, which is pure stdlib.

What a failure here means:
  - missing require()      -> the tool is reachable by ANY authenticated principal,
                              because the coarse connection gate is the only check left.
  - wrong name in require() -> the tool is authorized against some OTHER tool's
                              policy row, the classic copy-paste bug.
  - missing policy entry    -> authorize_tool() returns 'no-policy' and denies, so the
                              tool is dead code that looks live.
  - stale policy entry      -> authz_editor derives its known_tools allowlist from
                              _DEFAULT_TOOL_GROUPS, so a key with no tool behind it
                              becomes an editable phantom tool in the admin UI.

Run: python -m unittest (from tests/python)."""
import ast
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, os.path.join(REPO, 'server'))

import authz                                            # noqa: E402

SERVER_SRC = os.path.join(REPO, 'server', 'mcp_server.py')


def _decorator_names(node):
    """Dotted names of every decorator on node, e.g. 'mcp.tool' for both
    @mcp.tool and @mcp.tool(). Unresolvable decorator expressions are skipped."""
    names = []
    for dec in node.decorator_list:
        expr = dec.func if isinstance(dec, ast.Call) else dec
        parts = []
        while isinstance(expr, ast.Attribute):
            parts.append(expr.attr)
            expr = expr.value
        if isinstance(expr, ast.Name):
            parts.append(expr.id)
            names.append('.'.join(reversed(parts)))
    return names


def _collect_tools(tree):
    """Every function decorated with @mcp.tool, at any nesting depth."""
    tools = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if 'mcp.tool' in _decorator_names(node):
                tools.append(node)
    return tools


def _body_after_docstring(fn):
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        return body[1:]
    return body


def _calls_named(node, fname):
    """Every call to a bare fname(...) inside node."""
    return [n for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == fname]


def _require_calls(node):
    """Every call to a bare require(...) inside node."""
    return _calls_named(node, 'require')


def _forward_calls(node):
    """Every call to a bare forward_header(...) inside node."""
    return _calls_named(node, 'forward_header')


def _second_positional_string(call):
    """The second positional argument if it is a string literal, else None. A
    non-literal (a variable, an f-string, a concatenation) is deliberately NOT
    accepted: the whole point is that the audited tool name is reviewable in the
    source, not computed at runtime."""
    if len(call.args) < 2:
        return None
    arg = call.args[1]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    return None


with open(SERVER_SRC, 'r', encoding='utf-8') as _f:
    _TREE = ast.parse(_f.read(), filename=SERVER_SRC)

TOOLS = _collect_tools(_TREE)
TOOL_NAMES = [t.name for t in TOOLS]


class ToolDiscovery(unittest.TestCase):
    """The parse itself has to find something, or every assertion below passes
    vacuously and the invariant is silently unenforced."""

    def test_tools_were_found(self):
        self.assertTrue(TOOLS, 'no @mcp.tool functions found in %s' % SERVER_SRC)

    def test_tool_names_are_unique(self):
        self.assertEqual(sorted(TOOL_NAMES), sorted(set(TOOL_NAMES)),
                         'duplicate @mcp.tool function names: %r' % (TOOL_NAMES,))


class EveryToolCallsRequire(unittest.TestCase):
    """SECURITY.md item 12, forward direction: tool -> require() -> policy."""

    def test_every_tool_calls_require_with_its_own_name(self):
        for fn in TOOLS:
            with self.subTest(tool=fn.name):
                calls = _require_calls(fn)
                self.assertTrue(calls, '%s does not call require()' % fn.name)
                named = [_second_positional_string(c) for c in calls]
                self.assertIn(fn.name, named,
                              '%s calls require() but never with its own name (saw %r)'
                              % (fn.name, named))

    def test_require_is_the_first_statement_after_the_docstring(self):
        # Anything executed before the gate runs unauthorized, however harmless it
        # looks today. Keeping the call in position 0 makes that reviewable at a
        # glance instead of by reading the whole body.
        for fn in TOOLS:
            with self.subTest(tool=fn.name):
                body = _body_after_docstring(fn)
                self.assertTrue(body, '%s has an empty body' % fn.name)
                first = _require_calls(body[0])
                self.assertTrue(first,
                                '%s: first statement after the docstring is not a require() call'
                                % fn.name)
                self.assertEqual(_second_positional_string(first[0]), fn.name,
                                 '%s: the leading require() names a different tool' % fn.name)

    def test_no_tool_requires_someone_elses_name(self):
        # A copy-pasted body that gates on another tool's row is authorized, just
        # against the wrong policy. Catch it even if the correct call is also present.
        for fn in TOOLS:
            for call in _require_calls(fn):
                name = _second_positional_string(call)
                with self.subTest(tool=fn.name, requires=name):
                    self.assertIsNotNone(
                        name,
                        '%s: require() second argument is not a string literal' % fn.name)
                    self.assertEqual(name, fn.name,
                                     '%s calls require(ctx, %r)' % (fn.name, name))

    def test_every_tool_has_a_policy_entry(self):
        for name in TOOL_NAMES:
            with self.subTest(tool=name):
                self.assertIn(name, authz._DEFAULT_TOOL_GROUPS,
                              'tool %r has no TOOL_GROUPS entry; authorize_tool() would '
                              'return no-policy and deny it' % name)


class PolicyHasNoPhantomTools(unittest.TestCase):
    """Reverse direction. authz_editor derives its known_tools allowlist from
    _DEFAULT_TOOL_GROUPS, so a leftover key is an editable tool that does not
    exist, and it silently widens what the optional policy editor accepts."""

    def test_every_policy_key_maps_to_a_tool(self):
        for name in authz._DEFAULT_TOOL_GROUPS:
            with self.subTest(policy_entry=name):
                self.assertIn(name, TOOL_NAMES,
                              'TOOL_GROUPS entry %r has no @mcp.tool behind it' % name)

    def test_policy_values_are_well_formed(self):
        # A bare string here would be iterated character by character by the
        # set-intersection in authorize_tool, matching single-letter group names.
        for name, groups in authz._DEFAULT_TOOL_GROUPS.items():
            with self.subTest(policy_entry=name):
                if groups is authz.ANY_AUTHENTICATED:
                    continue
                self.assertIsInstance(groups, (set, frozenset),
                                      'TOOL_GROUPS[%r] must be a set of group names or '
                                      'ANY_AUTHENTICATED' % name)
                self.assertTrue(groups, 'TOOL_GROUPS[%r] is an empty set, which denies '
                                        'everyone; use a real group or remove the tool' % name)
                for g in groups:
                    self.assertIsInstance(g, str, 'TOOL_GROUPS[%r] holds a non-string' % name)




class ForwardHeaderIsGatedTheSameWay(unittest.TestCase):
    """SECURITY.md [D1]. forward_header() selects the DOWNSTREAM SERVICE a tool may
    reach as the caller, from authz.TOOL_TARGETS keyed by tool name. It needs
    exactly the discipline require() already has, and for a sharper reason.

    require() had a second line of defence: even if a tool passed the wrong name,
    the caller still had to be in some IPA group. forward_header has none. The KDC
    was supposed to be that backstop, and it is not one against a hostile client:
    a caller who sets GSS_C_DELEG_FLAG hands the server a full forwarded TGT and
    the KDC will then issue tickets to anything that caller could reach. Proven on
    a live KDC. So TOOL_TARGETS is the only thing standing between a mislabelled
    call and a token minted for the wrong downstream, carrying the caller's own
    identity."""

    def test_forward_header_is_called_with_a_literal_tool_name(self):
        # A computed label is the request-forgery case: if it can be influenced by
        # a tool argument, the caller chooses the downstream service.
        for fn in TOOLS:
            for call in _forward_calls(fn):
                with self.subTest(tool=fn.name):
                    self.assertIsNotNone(
                        _second_positional_string(call),
                        '%s calls forward_header() with a non-literal tool name; '
                        'the target must never be computable from a request' % fn.name)

    def test_forward_header_uses_the_tools_own_name(self):
        for fn in TOOLS:
            calls = _forward_calls(fn)
            if not calls:
                continue
            with self.subTest(tool=fn.name):
                named = [_second_positional_string(c) for c in calls]
                self.assertEqual(
                    [fn.name], sorted(set(n for n in named if n is not None)),
                    '%s forwards under a name that is not its own (saw %r); that '
                    'reaches another tool policy row downstream target' % (fn.name, named))

    def test_a_forwarding_tool_still_calls_require_first(self):
        # forward_header deliberately does not re-check authorization. A tool that
        # forwarded without gating would hand out a caller-identity token to any
        # authenticated principal.
        for fn in TOOLS:
            if not _forward_calls(fn):
                continue
            with self.subTest(tool=fn.name):
                body = _body_after_docstring(fn)
                self.assertTrue(_require_calls(body[0]),
                                '%s forwards but does not call require() first' % fn.name)

    def test_no_target_policy_row_names_a_tool_that_cannot_forward(self):
        # Deliberately this direction, not the other one. A forwarding tool with no
        # target is FINE and is the shipped state: it fails closed at runtime until
        # an operator names one. A target row with no forwarding tool is the
        # dangerous direction, because it is a live grant sitting unused, waiting
        # for some future function to be given that name.
        import delegation
        forwarding = {fn.name for fn in TOOLS if _forward_calls(fn)}
        for tool in authz.TOOL_TARGETS:
            with self.subTest(tool=tool):
                self.assertIn(tool, forwarding,
                              'authz.TOOL_TARGETS grants %r a downstream target, '
                              'but no tool by that name calls forward_header' % tool)


if __name__ == '__main__':
    unittest.main()
