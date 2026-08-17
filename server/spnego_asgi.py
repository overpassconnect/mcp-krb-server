"""spnego_asgi.py - self-contained SPNEGO/Kerberos ASGI auth middleware.

Drop it in front of any ASGI app (e.g. the MCP SDK's streamable_http_app()):

    from spnego_asgi import SpnegoAuthMiddleware, SCOPE_PRINCIPAL
    app = SpnegoAuthMiddleware(inner_app, spn='HTTP@mcp.example', authorize=fn)

It authenticates every HTTP request with Kerberos (via spnego_auth.py, which is
validated against a real KDC), stashes the validated principal on the request
scope for downstream handlers/tools to read (scope[SCOPE_PRINCIPAL] /
request.scope[...]), and rejects (401/403) before the wrapped app runs.

Security properties:
  [C1] true-completeness gate + krb5-only + principal validation (all in spnego_auth).
  [C4] the client gets a bare 401/403; the real reason goes only to the audit sink.
  per-request auth: pair with the SDK's stateless_http=True so there is no session
       id acting as a bearer credential (nothing to steal/reuse).

Non-http scopes (lifespan, websocket) pass through untouched; without that the
wrapped SDK app's session-manager lifespan never starts. The module depends only
on spnego_auth (+ python3-gssapi), not on the MCP SDK.
"""
import json
import sys

import spnego_auth

SCOPE_PRINCIPAL = 'krb_principal'
# Where the per-request evidence credential is stashed when, and only when,
# on-behalf-of forwarding is enabled. Absent otherwise, so a tool that reads it
# without checking gets None and delegation.negotiate_header() fails closed.
SCOPE_EVIDENCE = 'krb_evidence'


def _default_audit(event):
    sys.stderr.write(json.dumps(event) + '\n')
    sys.stderr.flush()


class SpnegoAuthMiddleware:
    def __init__(self, app, spn, authorize, audit=None, scope_key=SCOPE_PRINCIPAL,
                 delegation=False, keytab=None):
        if not callable(authorize):
            raise ValueError('authorize(principal)->bool is required (deny by default)')
        self.app = app
        self.authorize = authorize
        self.scope_key = scope_key
        self.audit = audit or _default_audit
        # delegation=False is the default and keeps the acceptor receive-only [C2].
        # When it is on, the acceptor can also initiate, which is what lets the KDC
        # compose an evidence credential naming the caller. See spnego_auth and
        # delegation.py; enabling it is a deployment decision, not a code default.
        self.delegation = bool(delegation)
        # Not make_acceptor_creds directly: with delegation on, the credential
        # carries a TGT that dies after a day, and holding one object for the
        # life of the process is how a healthy-looking server silently stops
        # being able to delegate. See RenewingAcceptorCredentials. It acquires
        # once here, so an unusable SPN or keytab still fails fast at startup.
        self._creds = spnego_auth.RenewingAcceptorCredentials(   # explicit SPN [C2]
            spn, keytab=keytab, delegation=self.delegation)

    @property
    def creds(self):
        """The acceptor credential, re-acquired if it is spent. A property, so
        every read goes through the freshness check rather than only the reads
        that remembered to."""
        return self._creds.get()

    async def __call__(self, scope, receive, send):
        if scope.get('type') != 'http':
            await self.app(scope, receive, send)            # lifespan/websocket passthrough
            return

        headers = dict(scope.get('headers') or [])
        auth = headers.get(b'authorization', b'').decode('latin-1')
        client_ip = self._client_ip(scope, headers)
        path = scope.get('path', '')
        method = scope.get('method', '')

        evidence = None
        try:
            if self.delegation:
                principal, _resp, evidence = spnego_auth.authenticate(
                    self.creds, auth, want_evidence=True)
            else:
                principal, _resp = spnego_auth.authenticate(self.creds, auth)
        except spnego_auth.AuthError as e:
            await self._deny(send, 401, e.reason, client_ip, method, path)
            return
        if not self.authorize(principal):
            await self._deny(send, 403, 'not-authorized:' + principal, client_ip, method, path)
            return

        scope[self.scope_key] = principal
        # Per-request and never cached: the evidence belongs to this caller, and
        # holding it beyond the request would let one caller's credential be used
        # for another's call.
        if self.delegation:
            scope[SCOPE_EVIDENCE] = evidence
        self.audit({'event': 'auth', 'outcome': 'allow', 'principal': principal,
                    'clientIp': client_ip, 'method': method, 'path': path})
        await self.app(scope, receive, send)

    def _client_ip(self, scope, headers):
        xff = headers.get(b'x-forwarded-for')
        if xff:
            return xff.decode('latin-1')
        client = scope.get('client')
        return client[0] if client else '?'

    async def _deny(self, send, code, reason, ip, method, path):
        self.audit({'event': 'auth', 'outcome': 'deny', 'code': code, 'reason': reason,
                    'clientIp': ip, 'method': method, 'path': path})
        hdrs = [(b'content-type', b'text/plain')]
        if code == 401:
            hdrs.append((b'www-authenticate', b'Negotiate'))
        body = b'authentication required\n' if code == 401 else b'forbidden\n'
        await send({'type': 'http.response.start', 'status': code, 'headers': hdrs})
        await send({'type': 'http.response.body', 'body': body})
