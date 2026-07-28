"""spnego_auth.py - hardened SPNEGO/Kerberos acceptor for the Python MCP server.

The central guarantee [C1]: a half-finished GSS context is never treated as
authenticated. An acceptor that filled in a username before the handshake
completed (never checking GSS_S_CONTINUE_NEEDED) would be an NTLM-multi-leg
pre-auth bypass. This one cannot: python-gssapi exposes the true GSS status via
`ctx.complete` (RFC 2743/2744), and this code gates strictly on it plus a
validated principal, so that bug class is structurally impossible here.

Controls (see ../SECURITY.md):
  [C1] gate strictly on ctx.complete (true GSS completeness) plus a validated
       principal; also reject NTLM tokens up front and pin the accepted mech.
  [C2] acquire acceptor creds for an explicit SPN only, never the default or any.
  [C3] treat the principal as untrusted: validate against a strict allowlist.
  [C4] never reflect GSSAPI detail to the client: raise AuthError with a short
       reason for the server-side audit; the caller returns a bare 401/403.
  [C6] bound unauthenticated work: reject oversized or garbage tokens before crypto.

Requires: python3-gssapi (ships on ipa-client machines), KRB5_KTNAME (set in the systemd unit)
pointing at the HTTP/<fqdn> keytab, and a KRB5-only GSS stack (no gss-ntlmssp).
"""
import base64
import re
import gssapi
from gssapi.exceptions import GSSError

KRB5_MECH = gssapi.OID.from_int_seq('1.2.840.113554.1.2.2')
SPNEGO_MECH = gssapi.OID.from_int_seq('1.3.6.1.5.5.2')
_ACCEPTED_MECHS = (KRB5_MECH, SPNEGO_MECH)   # SPNEGO wrapping krb5 (krb5-only host)

MAX_TOKEN_B64 = 64 * 1024
# Where the service keeps its own ticket cache when delegation is enabled. Under
# the systemd unit this is RuntimeDirectory=mcp-server, so it is tmpfs, mode 0755
# on the directory, and destroyed on stop. Deliberately not /tmp: that is
# world-writable with a predictable name, and not the ambient KRB5CCNAME either,
# for the reason spelled out in make_acceptor_creds.
DEFAULT_SERVICE_CCACHE = '/run/mcp-server/krb5cc'
# local[/instance]@REALM, conservative charset: rejects spaces, control chars,
# backslash escapes and multiple '@' (anything an injection would need).
PRINCIPAL_RE = re.compile(
    r'^[A-Za-z0-9._-]{1,64}(?:/[A-Za-z0-9._-]{1,128})?@[A-Z0-9.-]{2,128}$')
# NTLMSSP signature and the NTLM mech OID inside a SPNEGO NegTokenInit (base64
# fragments). Defense-in-depth on top of the deployment krb5-only guarantee.
_NTLM_MARKERS = ('TlRMTVNTU', 'KwYBBAGCNwIC')


class AuthError(Exception):
    """Authentication failed. `reason` is a short slug for the audit log only:
    never send it to the client."""
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def make_acceptor_creds(spn, keytab=None, delegation=False, ccache=None):
    """Acquire acceptor credentials for an explicit hostbased SPN [C2].
    e.g. spn='HTTP@mcp.example.internal'. Call once at startup.

    delegation=False (the default, and what you want unless you have deliberately
    enabled on-behalf-of forwarding) acquires usage='accept': the credential can
    only receive. It cannot initiate a connection anywhere, so a compromise of
    this process cannot use it to reach out as anyone.

    delegation=True acquires usage='both' and adds the keytab as a client keytab.
    That changes what the credential is: 'both' is the documented MIT precondition
    for the KDC to compose an evidence credential naming the caller (see
    delegation.py). With usage='accept' the accepted context's delegated_creds is
    always None no matter what the caller sends, so constrained delegation is
    simply unreachable. Verified on a live KDC.

    The cost, stated plainly because it narrows [C2]: the service keytab becomes
    usable for outbound authentication, not only inbound. The bound on it is the
    KDC rather than this process: the KDC issues onward tickets only to principals
    on the FreeIPA servicedelegationtarget allowlist, and only when the caller's
    own ticket is presented as evidence, so this credential cannot reach a service
    the realm has not explicitly approved and cannot act for anyone who did not
    call. Verified against a live KDC, including the negative case: a different
    service on the same host is refused."""
    if not spn or '@' not in spn:
        raise ValueError('an explicit hostbased SPN is required, e.g. "HTTP@host" [C2]')
    name = gssapi.Name(spn, gssapi.NameType.hostbased_service)
    if not delegation:
        return gssapi.Credentials(name=name, usage='accept')
    if not keytab:
        # Fail closed rather than silently falling back to the ambient default
        # keytab, which may not be the one this SPN lives in.
        raise ValueError('delegation=True requires an explicit keytab path')
    # An explicit ccache, never the ambient default. usage='both' makes MIT
    # acquire initiator material too, and it will happily adopt whatever
    # KRB5CCNAME points at. If that cache holds a different principal the
    # acquisition dies with "Principal in credential cache does not match desired
    # name", and if it holds a useful one the service would quietly initiate as
    # somebody else. Naming our own cache removes both, and makes the service
    # independent of the environment it happens to inherit.
    store = {'keytab': keytab, 'client_keytab': keytab,
             'ccache': ccache or ('FILE:' + DEFAULT_SERVICE_CCACHE)}
    return gssapi.Credentials(name=name, usage='both', store=store)


def authenticate(acceptor_creds, authorization_header, want_evidence=False):
    """Validate one 'Authorization: Negotiate <b64>' header.

    Returns (principal, response_token_b64_or_None) on success; raises AuthError
    otherwise. Single-leg Kerberos completes in one step; anything that does not
    complete in one step (e.g. an NTLM negotiation) is rejected.

    want_evidence=True returns (principal, response, evidence_cred) instead, where
    evidence_cred is the credential naming the caller that MIT composed from the
    ticket they presented. It is None unless the acceptor credential was acquired
    with delegation=True, and None is always a valid answer: callers must treat it
    as "cannot forward" and fail closed, never as "forward as myself".

    What this credential actually is depends on the caller, and the difference
    matters. If the caller did not delegate, it is a narrow evidence credential:
    proof they authenticated here, usable only to obtain a ticket to a target the
    KDC has approved. If the caller did set GSS_C_DELEG_FLAG, it is their full
    forwarded TGT, and the KDC will then issue a ticket to anything that caller
    could reach.

    This function does not distinguish them, and deliberately does not try: it
    returns whatever MIT composed. delegation.is_narrow_evidence() makes that call,
    at the point of use, where the acceptor's own principal is known to compare
    against. A non-None return here is not safe to forward on its own. (An earlier
    revision of this docstring asserted the credential was never a TGT, and a later
    one asserted the two could not be told apart. Both were wrong; see
    ../SECURITY.md [D1] for the mechanism and the live evidence.)"""
    hdr = authorization_header or ''
    if not hdr.startswith('Negotiate '):
        raise AuthError('no-negotiate-header')
    b64 = hdr[len('Negotiate '):].strip()
    if not b64 or len(b64) > MAX_TOKEN_B64:            # [C6]
        raise AuthError('token-size')
    for m in _NTLM_MARKERS:                            # [C1] defense-in-depth
        if b64.startswith(m) or m in b64:
            raise AuthError('ntlm-token-rejected')
    try:
        token = base64.b64decode(b64, validate=True)
    except Exception:
        raise AuthError('bad-base64')

    ctx = gssapi.SecurityContext(creds=acceptor_creds, usage='accept')
    # python-gssapi defers accept errors: ctx.step() may return without raising,
    # and the GSSError (e.g. "Request is a replay") surfaces on the next attribute
    # access, so every context read below must be inside this try [C4].
    try:
        out = ctx.step(token)
        complete = ctx.complete
        mech = ctx.mech if complete else None
        principal = str(ctx.initiator_name) if complete else None
        # Read inside the same try: python-gssapi defers accept errors, so this
        # attribute can raise just like the ones above. Only read it when asked,
        # so the default path touches nothing extra.
        evidence = (ctx.delegated_creds if (want_evidence and complete) else None)
    except GSSError as e:
        raise AuthError('gss-error:%s' % e)            # audited, never reflected

    # [C1] the real gate: python-gssapi reflects true GSS completeness.
    if not complete:
        raise AuthError('context-incomplete')
    # krb5-only: refuse any mech that is not krb5 / SPNEGO(krb5).
    if mech not in _ACCEPTED_MECHS:
        raise AuthError('non-krb5-mech')
    if not PRINCIPAL_RE.match(principal):             # [C3]
        raise AuthError('principal-malformed')

    resp = base64.b64encode(out).decode() if out else None
    if want_evidence:
        return principal, resp, evidence
    return principal, resp
