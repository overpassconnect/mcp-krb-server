#!/usr/bin/env python3
"""mcp_server.py - MCP server on the official SDK (mcp>=1.28), Kerberos-authenticated.

Architecture:
  - FastMCP handles the MCP protocol (streamable HTTP).
  - spnego_asgi.SpnegoAuthMiddleware wraps the SDK's ASGI app and authenticates
    every request via Kerberos before the MCP layer runs (auth is sealed; tools
    never see the acceptor, headers, or session).
  - stateless_http=True: no server-side session, so no Mcp-Session-Id bearer to
    steal or reuse. Every request is independently Kerberos-authenticated [S1 moot].

Separation of duties (see ../SECURITY.md):
  - The authorization policy below (who may call which tool) is security-owned.
    Put it under CODEOWNERS review; tool developers do not edit it.
  - The tool implementations are dev-owned; each one's first line calls
    require(ctx, '<tool>'), which returns the authenticated principal only if the
    security-owned policy allows it (deny by default). A CI check asserts that
    every @mcp.tool calls require() with its own name and has a policy entry.

Deps: mcp, uvicorn, starlette, pydantic (server box only; see SECURITY.md for the
offline/internal-mirror install; the client bridge stays stdlib). Run by
mcp-server.service under uvicorn behind nginx over a UNIX socket.
"""
import json
import os
import sys

from mcp.server.fastmcp import FastMCP, Context
from mcp.server.transport_security import TransportSecuritySettings

import authz
import authz_editor
import delegation
from spnego_asgi import SpnegoAuthMiddleware, SCOPE_PRINCIPAL, SCOPE_EVIDENCE

SPN = os.environ.get('MCP_SPN', 'HTTP@mcp.example.internal')
LISTEN = os.environ.get('MCP_LISTEN', '/run/mcp-server/mcp.sock')

# The same identity as SPN, in Kerberos principal form rather than GSS hostbased
# form: 'HTTP@host' -> 'HTTP/host@REALM'. delegation.is_narrow_evidence() compares
# the credential's impersonator field against this to confirm that this acceptor
# composed it. Derived rather than configured separately, so the two can never
# disagree; a mismatch would fail closed and disable forwarding entirely, which is
# noisy but safe. Uses the same MCP_REALM the authz allowlist already reads.
_SPN_SERVICE, _, _SPN_HOST = SPN.partition('@')
SPN_PRINCIPAL = '%s/%s@%s' % (_SPN_SERVICE, _SPN_HOST,
                              os.environ.get('MCP_REALM', 'EXAMPLE.INTERNAL'))

# ======================= security-owned (CODEOWNERS) =========================
# The who-may-call-what policy and the IPA group lookup live in authz.py (no MCP
# dependency, unit-testable on its own). This file wires it in and audits. Tool
# developers add tools below; they do not touch authz.py without security review.
# See ../SECURITY.md [S2].


def _audit(event):
    sys.stderr.write(json.dumps(event) + '\n')
    sys.stderr.flush()


def require(ctx, tool):
    """First line of every tool. Returns the authenticated principal only if the
    security-owned per-tool IPA-group policy (authz.authorize_tool) allows it;
    otherwise raises PermissionError. Audits the decision either way, so every
    attempt (allowed or denied) is logged against the real Kerberos principal
    [S2], making a malicious or tampered client's attempts visible and
    attributable. The tool name is truncated (attacker-controlled) and the whole
    event JSON-encoded (no log injection via control chars)."""
    req = ctx.request_context.request                 # Starlette Request (HTTP); None on stdio
    principal = req.scope.get(SCOPE_PRINCIPAL) if req is not None else None
    tool_label = str(tool)[:128]
    if not principal:
        _audit({'event': 'tool.call', 'tool': tool_label, 'allowed': False, 'reason': 'unauthenticated'})
        raise PermissionError('unauthenticated')
    allowed, detail = authz.authorize_tool(principal, tool)
    _audit({'event': 'tool.call', 'principal': principal, 'tool': tool_label,
            'allowed': allowed, 'detail': detail})
    if not allowed:
        raise PermissionError('not authorized for tool: ' + tool_label)
    return principal


def forward_header(ctx, tool):
    """Second line of a tool that calls a downstream service as the caller.

    Returns an 'Authorization: Negotiate ...' value that authenticates to that
    tool's allowlisted target as the user, so the downstream sees the real human
    rather than this service account. Call require() first: this deliberately does
    not re-check authorization, it only forwards.

    Fails closed on every path, and 'closed' means raising, never falling back to
    our own identity. A silent fallback would still work, which is what makes it
    dangerous: the downstream would attribute the action to the MCP service and
    nobody would notice the attribution was lost.

    The target comes from delegation.TOOL_TARGETS keyed by the tool name. It is
    never taken from an argument: a caller-chosen target is request forgery with
    the caller's own identity attached.

    Passing SPN_PRINCIPAL lets delegation.is_narrow_evidence() confirm the
    credential is an S4U2Proxy evidence credential composed by this acceptor, and
    not the caller's full forwarded TGT. Without that check a modified client
    could hand us a TGT and reach anything they can reach, allowlist or not."""
    req = ctx.request_context.request
    evidence = req.scope.get(SCOPE_EVIDENCE) if req is not None else None
    try:
        return delegation.negotiate_header(evidence, tool, SPN_PRINCIPAL, audit=_audit)
    except delegation.DelegationError as e:
        _audit({'event': 'delegate', 'outcome': 'deny', 'tool': str(tool)[:128],
                'reason': e.reason})
        raise PermissionError('cannot act on your behalf for tool: ' + str(tool)[:128])
# ============================================================================


mcp = FastMCP(
    'mcp-krb-server',
    stateless_http=True,     # no session bearer [S1 moot]; ideal behind nginx
    json_response=True,      # plain application/json instead of an SSE stream
    streamable_http_path='/',   # serve at root so clients keep pointing at the base URL
    # We terminate at a UNIX socket behind nginx and do our own auth, so turn off
    # FastMCP's auto Host-allowlist (else nginx's Host header is rejected 421).
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

# --------------------------- dev-owned tools --------------------------------
@mcp.tool()
def whoami(ctx: Context) -> str:
    """Return the caller's authenticated Kerberos principal."""
    p = require(ctx, 'whoami')
    return 'You are ' + p


@mcp.tool()
def list_projects(ctx: Context) -> str:
    """List projects visible to the caller."""
    p = require(ctx, 'list_projects')
    return 'projects for ' + p + ': (stub)'


@mcp.tool()
def restart_service(name: str, ctx: Context) -> str:
    """Restart a managed service (privileged)."""
    p = require(ctx, 'restart_service')
    return 'would restart %s as %s (stub)' % (name, p)


@mcp.tool()
def trigger_build(job: str, ctx: Context) -> str:
    """Trigger a CI build as the caller, so the downstream logs the human rather
    than this service.

    CI is just one example. Delegation forwards to any Kerberized downstream
    service the caller could reach: an internal REST API, a directory, a database
    proxy, a second MCP server. This tool illustrates the pattern with a CI build
    because "trigger a build as me" is easy to picture; the mechanism knows
    nothing about CI. Point TOOL_TARGETS at whatever service you actually forward
    to.

    The template for every forwarding tool. Copy this shape:

        p = require(ctx, '<my_own_name>')         # authorize, always first
        h = forward_header(ctx, '<my_own_name>')  # same literal, never computed
        ... send h as the Authorization header ...

    Both calls take this function's own name as a literal. Passing another tool's
    name would run under that tool's group policy or reach that tool's downstream
    service, and tests/python/test_tool_policy_invariant.py fails the build if
    either literal drifts.

    Inert until an operator sets MCP_DELEGATION=1 and names a target for
    'trigger_build' in MCP_DELEGATION_TARGETS; without both, forward_header raises
    and this returns an error rather than quietly acting as the service account.

    The HTTP call is left as a stub deliberately. Minting the ticket is the part
    that is hard to get right and the part this repo owns; which endpoint your
    downstream service exposes is site-specific, and a half-guessed request here
    would be a worse starting point than none. Send `h` as the Authorization
    header from whatever client you already trust."""
    p = require(ctx, 'trigger_build')
    h = forward_header(ctx, 'trigger_build')
    return ('would trigger %s as %s, carrying a Negotiate header naming that user '
            '(%d bytes, not shown) (stub)' % (job, p, len(h)))
# ----------------------------------------------------------------------------

# Wrap the SDK's Starlette app with the sealed Kerberos auth middleware.
# The optional authz policy editor is disabled by default: build_editor() returns
# None unless MCP_AUTHZ_EDITOR is set with a valid MCP_POLICY_ADMINS allowlist. When
# disabled, the dispatcher is never installed and this is byte-identical to before.
_inner = mcp.streamable_http_app()
_editor = authz_editor.build_editor(_audit)
_root = authz_editor.Dispatch(_inner, _editor) if _editor is not None else _inner
# delegation=... is read from the environment, not hardcoded: with MCP_DELEGATION
# unset the acceptor stays receive-only [C2] and no evidence credential is ever
# requested, so this is byte-identical to the non-forwarding server.
app = SpnegoAuthMiddleware(_root, spn=SPN, authorize=authz.authorize_connection,
                           delegation=delegation.enabled(),
                           keytab=os.environ.get('KRB5_KTNAME'))


def main():
    import uvicorn

    # The socket's group and mode are set by ExecStartPost in the unit, which
    # runs as root via the '+' prefix. This process cannot do it: the sandbox
    # gives it an empty CapabilityBoundingSet and NoNewPrivileges=yes, so it has
    # no CAP_CHOWN. uvicorn creates the uds at 0666, and without that post-step
    # any local account able to traverse the directory can speak HTTP straight to
    # this app, skipping nginx's rate limit, its body cap, and the
    # X-Forwarded-For overwrite that audit attribution depends on.
    if LISTEN.startswith('/'):
        try:
            os.unlink(LISTEN)
        except FileNotFoundError:
            pass
        uvicorn.run(app, uds=LISTEN)          # nginx proxies to this socket
    else:
        host, port = LISTEN.rsplit(':', 1)
        uvicorn.run(app, host=host or '127.0.0.1', port=int(port))


if __name__ == '__main__':
    main()
