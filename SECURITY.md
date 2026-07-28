# Security review - Claude Code ⇄ Kerberized MCP server (Python)

## Reporting a vulnerability

Report privately, not in a public issue or pull request. Email
security@overpassconnect.com with a description, affected version or commit, and
reproduction steps. You will get an acknowledgement, and a fix or a decision with reasons.
Please allow a reasonable window before any public disclosure.

Supported: the tip of the default branch. This repository has no tagged releases
yet; when it does, this line should name the supported ones.

Everything below this section is a security review (threat model, findings,
deployment checklist), not the reporting policy. It is meant to be read by
operators and reviewers.

---

Scope: the Python client bridge, the Python MCP server + SPNEGO
acceptor, the nginx/systemd deployment, provisioning, and the Windows
workstation SSH kit (`client/`, PowerShell + WSL2, for
non-domain-joined Windows 11). Environment: FreeIPA-enrolled Linux, MIT krb5,
nginx terminating TLS in front of the app.

Out of scope: the host that serves the client bundle, as a system. By
default that is the MCP host itself, and only the nginx location serving the
bundle is in scope ([NG1]); the bytes it hands out are not. With
`--no-serve-client` the bundle is served from another machine the operator
copied it to, entirely their own system, no part of which lives in this repo.
Either way nothing below reviews the served bytes. [SC1] states exactly what that
costs, and the cost is not small: whoever controls those bytes can serve
anything to a root shell at enrolment and no client-side control would notice.

Each finding carries a status: fixed (closed in code here), deployment
(the code assumes it - your operational checklist), or residual (understand and
accept, or apply the named compensating control). Severity reflects a
>$500M-enterprise threat model.

---

## Contents

- [Standards compliance (what we conform to, and where)](#standards-compliance-what-we-conform-to-and-where)
- [CRITICAL](#critical)
  - [[C1] Acceptor must not treat an incomplete context as authenticated](#c1-acceptor-must-not-treat-an-incomplete-context-as-authenticated)
- [HIGH](#high)
  - [[R1] Replay protection (RFC 4120 §3.2.3 MUST) stays ON](#r1-replay-protection-rfc-4120-323-must-stays-on)
  - [[K1] Keytab theft on process compromise → service impersonation](#k1-keytab-theft-on-process-compromise--service-impersonation)
  - [[SC1] `curl | sh` as root at enrollment → fleet-wide RCE on publisher compromise](#sc1-curl--sh-as-root-at-enrollment--fleet-wide-rce-on-publisher-compromise)
  - [[S1] A session id is never a bearer credential](#s1-a-session-id-is-never-a-bearer-credential)
- [MEDIUM](#medium)
  - [[C2] Explicit SPN (never the default acceptor name)](#c2-explicit-spn-never-the-default-acceptor-name)
  - [[C3] The principal is untrusted input](#c3-the-principal-is-untrusted-input)
  - [[C4] No information disclosure](#c4-no-information-disclosure)
  - [[S2] Authentication ≠ authorization (per-tool, by IPA group)](#s2-authentication--authorization-per-tool-by-ipa-group)
  - [[S4-EDITOR] Optional browser editor for `TOOL_GROUPS` (DISABLED BY DEFAULT)](#s4-editor-optional-browser-editor-for-tool_groups-disabled-by-default)
  - [[C6] Bound unauthenticated work](#c6-bound-unauthenticated-work)
  - [[CB1] Channel binding unenforceable behind TLS-terminating nginx](#cb1-channel-binding-unenforceable-behind-tls-terminating-nginx)
  - [[NG1] nginx hardening](#ng1-nginx-hardening)
  - [[CL1] Clients: no token over plaintext, no credential delegation](#cl1-clients-no-token-over-plaintext-no-credential-delegation)
- [Threat model: a malicious or tampered client](#threat-model-a-malicious-or-tampered-client)
  - [[D1] On-behalf-of forwarding to a downstream service](#d1-on-behalf-of-forwarding-to-a-downstream-service)
- [LOW / operational (DEPLOYMENT)](#low--operational-deployment)
- [CVE inventory (consulted)](#cve-inventory-consulted)
- [Deployment checklist (invariants the code depends on)](#deployment-checklist-invariants-the-code-depends-on)
  - [TLS / private ACME (FreeIPA)](#tls--private-acme-freeipa)
- [Architecture note (Python + MCP SDK)](#architecture-note-python--mcp-sdk)
- [The test suite](#the-test-suite)
  - [Three layers](#three-layers)
  - [Running the unit tests](#running-the-unit-tests)
  - [What is in each test file](#what-is-in-each-test-file)
  - [Traceability (standard or finding to test)](#traceability-standard-or-finding-to-test)
  - [Honest limits](#honest-limits)
- [Verified](#verified)

---

## Standards compliance (what we conform to, and where)

| RFC | Requirement | Where it lives |
|---|---|---|
| RFC 2743/2744 GSS-API | distinguish `GSS_S_COMPLETE` vs `GSS_S_CONTINUE_NEEDED` | `spnego_auth.authenticate` gates on `ctx.complete` - the basis of the [C1] fix |
| RFC 4120 Kerberos V5 | replay cache MUST (§3.2.3); ~5-min clock skew; AP-REQ/AP-REP | enforced by the system MIT krb5 the acceptor calls; rcache left on [R1] - proven live (a reused token is rejected "Request is a replay") |
| RFC 4121 krb5 GSS mechanism | the only mechanism we accept | mech pin in `spnego_auth` (`_ACCEPTED_MECHS`) |
| RFC 4178 SPNEGO | negotiation wrapper (krb5 only, single-leg) | accepted; multi-leg never treated as complete [C1] |
| RFC 4559 SPNEGO HTTP | `WWW-Authenticate: Negotiate` challenge; `Negotiate <base64>` header; §6 headers unprotected → TLS required | server issues the challenge and parses the header. The bridge refuses a non-`http(s)` scheme outright, and refuses `http://` except to `localhost`, `127.0.0.1` or `::1`, where the token never leaves the machine. Anything remote uses HTTPS. [CL1] |
| RFC 5929 / 9266 channel binding | (not implemented - see [CB1]) | residual; low relay risk on Linux/HTTP |

---

## CRITICAL

### [C1] Acceptor must not treat an incomplete context as authenticated
Status: fixed by construction. An acceptor that sets the context "complete"
and fills the username before the GSS handshake finishes (never checking
`GSS_S_CONTINUE_NEEDED`) enables an NTLM-multi-leg pre-auth bypass. The Python
acceptor (`spnego_auth.py`) cannot: it gates strictly on `ctx.complete` (the real
GSS status per RFC 2743/2744), pins the mech to krb5/SPNEGO, rejects NTLM tokens
up front, and validates the principal. A half-finished context is never
authenticated.

*Verified:* live on the lab host (valid SPNEGO + raw-krb5 → principal; garbage, NTLM,
no-header, replay all rejected) and by hermetic unit tests including an explicit
`INCOMPLETE`-context case.

*Deployment:* krb5-only (no `gss-ntlmssp`) is still recommended hygiene so
SPNEGO cannot even offer NTLM; it is no longer the sole thing standing between
you and a bypass.

---

## HIGH

### [R1] Replay protection (RFC 4120 §3.2.3 MUST) stays ON
Status: fixed by default. Do not set `KRB5RCACHETYPE=none`: it disables a
MUST-level control and makes a logged `Authorization` token replayable within the
~5-min skew window. The bridge mints a fresh token per request (unique
authenticator), so the cache stays on with no churn. Proven live: a reused token
is rejected with the GSS reason "Request is a replay". nginx omits the
`Authorization` header from its access log.

### [K1] Keytab theft on process compromise → service impersonation
Status: residual (accepted) and deployment. The service process reads the keytab
directly: `/etc/mcp-server/krb5.keytab` is `root:<svcgroup> 0640` and the service
account can read it, because the in-process acceptor needs it. There is no
keytab isolation. Code execution in the service process therefore yields the
keytab, and with it the ability to impersonate `HTTP/mcp.example.internal` from
anywhere on the network - not just from this host - until the key is rotated. This
is not contained; it is an accepted risk.

What genuinely reduces the likelihood today, and nothing more:
- The systemd sandbox is real and running (verified on the host):
  `MemoryDenyWriteExecute=yes` (works with CPython + gssapi under the full
  sandbox), `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`,
  empty `CapabilityBoundingSet`, syscall filter. This raises the bar on turning a
  bug into code execution and blocks the usual escalation from there.
- nginx requires a valid Kerberos ticket before the app is reachable at all.
  An unauthenticated attacker cannot reach the process, so the exposure is to
  authenticated realm principals and to bugs in the acceptor path, not to the
  internet. (The two unauthenticated locations described in [NG1] serve static
  provisioning files and the ACME challenge; neither reaches the app.)

This acceptance assumes forwarding is off. If [D1] is enabled the prize grows:
the same stolen keytab additionally lets an attacker act as any user who has
called this server. Two bounds hold and one residual remains.

It holds that they cannot synthesise a ticket for a user who never authenticated
here, because protocol transition is off. It also holds that the KDC confines
them to the allowlisted targets, because [D1] refuses a forwarded TGT outright
(`is_narrow_evidence()`), so the credentials this process legitimately holds are
narrow evidence credentials that the realm's `servicedelegationtarget` list does
constrain. An earlier revision of this section said the opposite; it was written
before the discriminator was found, and it was wrong.

The residual: refusing to use a forwarded TGT is not the same as never receiving
one. MIT composes the credential during accept, so a caller who delegates puts
their TGT in this process's hands for the length of one request before it is
refused and dropped. An attacker with code execution here, not merely the keytab,
could harvest that. Two things bound it. The shipped client never delegates
([CL1], asserted by tests), so there is normally nothing to harvest; and a
delegating caller is by definition running modified software, which is a
different incident. Note the distinction from keytab theft: this residual needs
code execution on this host, while the paragraph above needs only the key file.

This is a decision worth making deliberately rather than inheriting, based on the
accurate version: the increment over "be this service" is bounded by what a
delegating caller could reach, in a fleet where no shipped client delegates.

Response to suspicion of compromise: rotate the keytab (`ipa-getkeytab` for
the SPN, which bumps the kvno and invalidates the stolen key), then restart the
unit. Treat any unexplained process compromise, host compromise, or backup/image
leak of `/etc/mcp-server/` as a rotation trigger. Do not wait for proof of use.

*Deployment:* one keytab contract, no alternatives - see checklist item 2. [K1]

> Optional future hardening (not deployed, not required): the standard answer
> to this residual is gssproxy, which holds the keytab out-of-process
> (`root:root 0400`) and hands the service only GSS operations over a socket, so
> process compromise buys the use of the credential while the process lives
> instead of the key itself. It is a real reduction and a real operational cost
> (a second daemon, its own mech.d plugin config, `GSS_USE_PROXY=1` in the unit,
> and a keytab custody model that differs from the one above). It has never been
> deployed here. If you pick it up, treat it as a new deployment mode with its own
> verification rather than a flag on this one.

### [SC1] `curl | sh` as root at enrollment → fleet-wide RCE on publisher compromise
Status: residual, accepted risk, not fixed. The label understates it; the finding
below states the full cost. The client kit is not signed. What protects it is TLS
and a CA pin; the rest is accepted.

Signing on the host that serves the files does not fix this. A signature
defends against a compromised publisher, so a signing key held by the publisher
defends against nothing the transport did not already cover, while costing a
duplicated verifier on every client and an out-of-band key to distribute. If you
want this closed, the key has to live somewhere the serving host cannot reach:
sign offline, or ship the client as a signed package in the base image.

What the clients actually do now.
- Artifacts are fetched over HTTPS from the publishing host. The scripts
  still never pipe a download to a shell: `install-bridge.sh` is written to a file and
  then executed, so there is no window in which a truncated download runs.
- On an enrolled Linux host the TLS leg is pinned to the realm CA
  (`/etc/ipa/ca.crt`), which `ipa-client-install` has just placed there. That
  narrows the hop from "any public CA" to "the CA this host was enrolled against".
  If the publisher's certificate does not chain to the realm
  CA, `setup.sh` announces it and retries on the system trust store, so at such a
  site that leg rests on public-CA TLS with no pin at all. That fallback does not
  arise when the MCP host serves the bundle, which is the default: its
  certificate is issued by the realm CA through FreeIPA's ACME service, so an
  enrolled machine fetching
  `install-bridge.sh` from it validates against the realm CA pin without the
  system-trust-store fallback. Proven live. The pin is no weaker in that
  arrangement, and in practice stronger than a publisher with a publicly issued
  certificate.
- On Windows, WSL is not enrolled and has no realm CA, so `client/setup.ps1`
  installs the realm CA into WSL's trust store and pins it by SHA-256
  (`-CaSha256`). That hash, delivered out of band, is now the only out-of-band
  trust root anywhere in the Windows path, and it survives the removal.
- `JsoncEdit.ps1` is fetched on plain TLS, and its pinned digest was removed for
  the same reason the signing chain was: the digest was substituted by the
  publisher into a script the publisher serves, so it only ever proved that host
  agreed with itself. Against a network attacker it added nothing TLS did not
  already give, and against a compromised publisher it added nothing at all. The
  helper now gets exactly the trust `install-bridge.sh` gets before being executed as
  root. One trust level for everything from that host, stated once, honestly.

What is accepted, in exactly these terms: a compromised publisher can serve
anything. It serves `install-bridge.sh`, which runs as root, and it serves the bridge.
No client-side control would notice. The clients verify that they reached the host
they were told to reach, over TLS, and nothing whatsoever about what that host chose
to hand them. Beyond that we hope the publishing host is not compromised. That is
the entire control on this axis and it is written that way on purpose. When the MCP host serves the bundle, which is the default, the serving host is
the MCP host, so this is the same host [K1] already treats as security-critical;
it does not make the risk smaller.

What the remaining posture does still buy, and no more:
- a network attacker who cannot terminate TLS for the publishing host cannot
  substitute bytes;
- on enrolled Linux where the pin holds, an attacker holding a mis-issued public
  CA certificate for the publisher's name still cannot, because the realm CA pin
  excludes the public PKI from that hop;
- no `curl | sh`, so no partial-download execution.

Deployment obligations (yours, not the code's).
1. Treat the publishing host as a fleet-wide root-code-execution dependency. It is
   one. Give it the custody, patch cadence, access control and monitoring you give
   the KDC. This is the compensating control, and it is operational, not technical.
2. Deliver `-CaSha256` out of band (MDM, Intune parameter, kickstart, printed
   handout) for every Windows workstation. Read it once from an enrolled host with
   `sha256sum /etc/ipa/ca.crt`. Unpinned means the CA is not installed, which
   makes the MCP step fail closed rather than trust-on-first-use.
3. If you serve the bundle from a separate host (`--no-serve-client` plus an exported
   copy), prefer one whose certificate chains to the realm CA, so the Linux pin
   actually holds instead of falling back. The default, the MCP host serving the
   bundle, satisfies this by construction, because the MCP host's certificate comes
   from the realm CA over FreeIPA ACME.

If you want real publisher-compromise protection, there are two options and both
move the trust root off the publishing host.
1. Sign offline, with a key that never touches the publisher: an airgapped or
   HSM-held key that signs artifacts before publication. This is what the removed
   chain was mistaken for.
2. Ship the client in a signed RPM in an internal dnf repo, via kickstart or the
   base image. Still the strongest option, because it moves the trust root onto
   the distro's existing package-signing chain, which is already operated, already
   has key custody, and is verified on every install with no parameter to pass and
   no second implementation to maintain.

### [S1] A session id is never a bearer credential
Status: fixed structurally, no session exists. The server runs the MCP SDK
in `stateless_http=True` mode, so there is no server-side session and no
`Mcp-Session-Id` acting as a bearer - every request is independently
Kerberos-authenticated by the ASGI middleware before the MCP layer runs. This is
strictly stronger than binding a session id to a principal (there is nothing to
steal or reuse), and it pairs exactly with the bridge's per-request tokens. The
bridge forwards an `Mcp-Session-Id` opaquely if it ever sees one and never treats
it as a credential; the server issues none and honours none. Verified
by the SDK smoke test (a `tools/call` succeeds and the tool reads the per-request
principal from the ASGI scope; no-auth/NTLM → 401).

---

## MEDIUM

### [C2] Explicit SPN (never the default acceptor name)
Status: fixed. `make_acceptor_creds` requires a hostbased SPN and acquires
acceptor creds for it only - a ticket for any other keytab principal is refused.

Narrowed by [D1] when on-behalf-of forwarding is enabled. The SPN is still
explicit and still the only one accepted. What changes is the credential's role:
with `MCP_DELEGATION` set it is acquired `usage='both'` rather than `usage='accept'`,
so it can also initiate outbound. Default remains `usage='accept'`, receive-only.
The delegation path also names an explicit ccache rather than inheriting the
ambient `KRB5CCNAME`, which would otherwise let the service initiate as whatever
principal happened to be cached in its environment.

### [C3] The principal is untrusted input
Status: fixed (validation) and deployment (downstream). Validated against a strict
allowlist regex; authorize on the full `user@REALM`. Note the regex intentionally
permits the `/` instance separator (legit `host/fqdn`), so a value like `../x@REALM`
is *syntactically* valid - any tool using `krbUser` in a path/SQL/shell must still
sanitize; prefer `principal` for decisions.

### [C4] No information disclosure
Status: fixed. GSSAPI/keytab/SPN detail and the principal are audited
server-side only; the client gets a bare 401/403.

### [S2] Authentication ≠ authorization (per-tool, by IPA group)
Status: fixed. Authorization lives in `server/authz.py` (who may call a tool)
and `server/delegation.py` (`TOOL_TARGETS`: what a tool may call onward). Both are
security-owned and carry no MCP dependency, so they are unit-testable on their
own. `TOOL_GROUPS` maps each tool to the
set of IPA groups whose members may call it (union; `ANY_AUTHENTICATED` for open
tools); a tool with no entry is denied. `authorize_tool()` resolves the caller's
groups via `ipa_groups()` and returns `(allowed, detail)`; the detail (matched
groups, or `no-group`/`no-policy`) is written to the audit log. `mcp_server.require()`
calls it as the first line of every tool and audits the decision either way.

`TOOL_TARGETS` is security-owned in-code policy and takes an operator overlay.
It works as two layers with one trust level between them. The in-code dict in
`delegation.py` is the reviewed floor and ships empty, because a real target is
a real hostname and this repo has none. At import, `delegation.py` runs
`TOOL_TARGETS.update(_targets_from_env(os.environ.get('MCP_DELEGATION_TARGETS')))`,
merging an operator overlay parsed from that environment variable. The overlay is
not a weaker channel: it arrives from a root-owned `EnvironmentFile` read by the
systemd unit, exactly like `MCP_DELEGATION` itself, and a collision with an
in-code row is fatal rather than resolved by precedence, so a deployment can
never silently redirect a target a reviewer approved. The full grammar, the caps,
and the fail-at-import behaviour are in [D1] under "Where targets come from".

The group lookup is now real rather than stubbed: `ipa_groups()` calls
`os.getgrouplist()` (nss → SSSD), which reads SSSD's local cache of the user's IPA
group membership - a fast local call with no per-request network and no
subprocess. It fails closed (any error → empty set → deny) and validates the
local part against a strict regex before touching nss (so junk never reaches the
resolver). The allow path is now tested both in isolation (`test_authz.py`: in-group
allows, out-of-group / extra-groups / unknown-tool deny, union, fail-closed lookup)
and end-to-end through the SDK (`test_mcp_server.py`: `restart_service` runs for an
`mcp-operators` member, denied otherwise).

Operating it (DX): the common change - who may call a tool - is a FreeIPA group
membership edit (add/remove the user in `mcp-operators` / `mcp-users` in the IPA web
UI), no code and no deploy; SSSD picks it up within its cache TTL. Only a
structural change (a new tool, or changing which group(s) a tool requires) edits
`TOOL_GROUPS`, which is a code review + deploy. Requires the server host to be
IPA-enrolled with SSSD resolving the relevant groups (`getent group mcp-operators`).

### [S4-EDITOR] Optional browser editor for `TOOL_GROUPS` (DISABLED BY DEFAULT)
Status: shipped, off by default. `server/authz_editor.py` adds an opt-in browser
editor for the per-tool policy. It was designed from a dedicated 19-agent CVE +
spec + threat review; the design decisions below are load-bearing.

- Disabled by default, and disabled means *absent*. `build_editor()` returns
  `None` unless `MCP_AUTHZ_EDITOR` is truthy and a valid `MCP_POLICY_ADMINS`
  allowlist is set (enabling with no valid admins logs and stays off - fail-closed).
  When off, the dispatcher is never installed, so the running server is
  byte-identical to before and `/admin/*` does not exist. No CVE/CSRF surface is
  added unless you deliberately turn it on.
- Reuses the proven auth, adds none. The editor sits behind
  `SpnegoAuthMiddleware`, so every request already passed the [C1] completeness
  gate, mech pin, and principal validation, and the principal is on the scope. It
  writes no new authentication code.
- Its own gate is code/config-pinned and separate from the policy it edits.
  Access is an exact-match principal allowlist (`MCP_POLICY_ADMINS`), not an IPA
  group (an IPA/KDC compromise must not mint a policy-admin) and not `admin@REALM`.
  Because the gate is not a `TOOL_GROUPS` entry, no edit can open the editor to
  others, add a policy-admin, or lock admins out of the editor.
- CSRF: Negotiate is ambient like a cookie, so the state-changing `PUT` enforces
  (fail-closed) an exact same-origin `Origin`, `Sec-Fetch-Site == same-origin` when
  present, and a strict `application/json` Content-Type checked from the header
  before the body is read (a JSON parser that ignores Content-Type cannot be relied
  on for this). There is no `GET`/simple-request path to the mutation and the app
  emits no CORS. The HTML is returned in-memory (no `FileResponse`) under a
  per-response nonce CSP.
- Persists data, never code. `PUT` writes a schema-validated JSON overlay
  (`authz.write_policy`: validate → atomic tmp+fsync+`os.replace` → apply), never
  rewrites `authz.py` (which would be RCE + a CODEOWNERS bypass). The reviewed
  in-code defaults remain the fail-safe floor: the overlay is merged *over* them,
  so a missing / corrupt / wiped file degrades to the reviewed defaults, never to
  open. `PUT` requires `If-Match` (428 if absent, 412 on mismatch) so concurrent
  admins can't lose-update. Every change emits a `policy.change` `{before, after}`
  audit event.
- Residuals (accepted, documented): (1) once enabled, the policy file is writable
  by the service, so an in-process RCE could persist a policy change across restart;
  the reviewed default remains the floor, and the max-hardening upgrade is to move the
  write into a separate privileged helper so the serving process keeps the file
  read-only. (2) The editor's unique power (remapping tool→group) is exactly what
  CODEOWNERS review catches, whereas *who-may-call* is already zero-code via IPA
  groups - so prefer leaving it off and only enable it where a live remap capability
  is genuinely wanted. A policy-admin is effectively root over the tool surface: keep
  the allowlist tiny.

Enabling it: uncomment the four `Environment=` lines + `StateDirectory` in
`mcp-server.service`, uncomment the `location /admin/` block in `nginx-mcp.nginx`
(it deliberately breaks the strict global CSP so the app's nonce CSP applies to that
page only), create the state dir, and restart. The admin's browser must trust the
host for Integrated Auth (as it must to reach the server at all). View at
`https://mcp.example.internal/admin/authz`.

### [C6] Bound unauthenticated work
Status: fixed. Oversized/garbage tokens rejected before crypto; nginx rate/conn
limits; 1 MB body cap.

### [CB1] Channel binding unenforceable behind TLS-terminating nginx
Status: residual (low risk here). python-gssapi could pass channel bindings, but
the app never sees the TLS layer (nginx terminates it), and GSS binding is
fail-open. Relay risk is low on Linux/FreeIPA (the weaponized corpus is
Windows/SMB; a curl/MIT client derives its SPN from the URL host). *Option for max
assurance:* validate SPNEGO at nginx with a maintained module and require binding.

### [NG1] nginx hardening
Status: fixed, with one open item named at the end of this finding. TLS 1.2/1.3
+ modern ciphers, HSTS, `nosniff`, tight CSP (`default-src 'none'; frame-ancestors
'none'`); 1 MB body cap plus body/header timeouts; access log omits `Authorization`;
`X-Forwarded-For` overwritten, not appended; UNIX-socket backend; :80→:443.
Server-level `limit_req`/`limit_conn` are set as defaults so that any location which
declares none inherits them.

What the vhost serves, stated precisely. An earlier revision of this finding
said the vhost "serves no static files at all". That was wrong, and wrong in
the direction that matters, because both exceptions are unauthenticated by
construction. There are exactly two:

1. The ACME challenge path on :80. `location ^~ /.well-known/acme-challenge/`
   serves from the webroot and is exempted from the HTTPS redirect inside a
   `location` block, not by a server-level `return`. It must be reachable without
   a ticket because the CA has none. See the TLS/ACME subsection for the failure
   mode when this is got wrong: issuance succeeds and the first *renewal* silently
   fails.
2. The client-bundle location on :443, present by default. run.sh replaces the
   `{{CLIENT_LOCATION}}` marker with a static `location ^~ $CLIENT_PATH` (default
   `/client/`) serving the client bundle (the five files plus the provisioning page).
   `--no-serve-client` replaces the marker with nothing, in which case the only
   unauthenticated path left is the ACME challenge one above. When the block exists it is
   deliberately unauthenticated, and that is required rather than incidental:
   nginx does not gate the API, the SPNEGO check lives in the application behind
   `location /`, so a static location never reaches it, and a machine being
   provisioned has no Kerberos ticket yet. Anything it must fetch in order to get a
   ticket cannot itself demand one. The files are provisioning scripts, not secrets.
   [SC1] is the finding that prices what serving them costs.

The generated client block deliberately declares no `limit_req`/`limit_conn`, so
it inherits the tighter server-level values instead of being the one uncapped
unauthenticated path on the host. Do not add a limit there without meaning to
*replace* the server-level ones: nginx does not merge them.

Open item (not fixed): the client-distribution block does not carry the security
headers. `add_header` is not inherited into a location that declares any
`add_header` of its own, and the generated block sets `add_header Cache-Control
...`. That single line stops HSTS, `nosniff` and the CSP from applying, so the one
unauthenticated location on the host is served without them. The block is emitted
from the `CLIENT_BLOCK` heredoc in `server/install/run.sh` (section 7), not from
`nginx-mcp.nginx`, so it cannot be fixed by editing the vhost template. The fix is
to restate the three server-level `add_header` lines inside that heredoc alongside
the existing `Cache-Control`. Until that lands, this stays open. It is low
severity (static provisioning scripts, no credentials, no app surface) and it is
still a gap, so it is written down rather than rounded to fixed.

### [CL1] Clients: no token over plaintext, no credential delegation
Status: fixed. The bridge refuses a scheme that is not `http`/`https` outright,
refuses `http://` to any host other than `localhost`, `127.0.0.1` or `::1` (where
the token never crosses a wire), and requests GSS init flags without
`delegate_to_peer` - so a compromised server can never obtain a forwardable TGT.

This applies to all clients, not just the bridge. The Windows workstation kit
enforces the same posture two ways: `GSSAPIDelegateCredentials no` in the managed
`ssh_config` block, and `forwardable = false` in the generated `krb5.conf`. The
second is strictly stronger, not a duplicate - a non-forwardable TGT cannot be
delegated even by a misconfigured client. Note the consequence: it also forecloses
the *evidence-based S4U2Proxy* path (calling another service as the caller).
[D1] now ships this (off by default), so this is no longer hypothetical: those
Windows workstations cannot use it until `forwardable` changes, because
`forwardable` must be revisited for Windows workstations.

---

## Threat model: a malicious or tampered client

The client bridge runs as the developer, with the developer's own Kerberos
ticket: it is a convenience layer that holds no trust of its own. A dev who edits
`mcp-krb-bridge.py` (or writes their own client) gains nothing they didn't
already have: they can already `curl --negotiate` as themselves and run
arbitrary code as their own user. Security lives entirely on the server, which
sees the real Kerberos principal and applies per-user / per-tool authorization. A
tampered client can only ever act as that developer - it cannot impersonate
anyone else (Kerberos), bypass auth (every request needs a valid ticket it can't
forge for another user), or reach a tool the policy denies.

| A malicious client attempts… | Server response |
|---|---|
| Forge/replay a token, present NTLM, oversized/garbage token | rejected before real work - completeness gate [C1], mech pin, size cap [C6], replay cache [R1] |
| Call a tool the dev may not use | denied by default [S2]; the attempt is audited with the real principal (`tool.call … allowed:false`) |
| Injection via tool arguments | args are untrusted (as always): the SDK validates them against each tool's schema; the tool code must still sanitize; per-tool authz limits who can even try |
| Flood / DoS | nginx per-IP rate + connection limits, 1 MB body cap; residual crypto cost is rate-limited [D1] |
| Poison / forge audit entries | the audit is JSON-encoded (control chars/newlines escaped - no log injection), the principal is regex-validated, attacker-controlled fields (tool name) are length-capped, and no token or raw args are logged (nginx omits `Authorization`) |

Decisive property: because Kerberos attributes every request to the real
principal and every tool attempt is audited, a malicious dev cannot act
anonymously or as someone else - abuse is least-privileged, rate-limited, and
fully attributable. The residual insider risk (misusing what they *are*
authorized to do) is bounded by per-tool RBAC and the security-owned policy,
rather than by trusting the client.

### [D1] On-behalf-of forwarding to a downstream service

Status: implemented, off by default. `server/delegation.py` lets a tool call a
downstream Kerberized service as the caller, so the downstream attributes the
action to the real human rather than to this service account. It uses
evidence-based S4U2Proxy constrained delegation and does not use protocol transition.

The trap. With the acceptor
credential acquired `usage='accept'`, `delegated_creds` is always `None`, no
matter what the caller sends. That reads as proof the whole approach is
impossible, and it is not: acquired `usage='both'` with a `client_keytab`, MIT
composes a credential naming the caller from the ticket they already presented.
Measured against a live KDC, not inferred. If you are here because a probe told
you evidence-based delegation cannot work from Python, check which usage the
probe asked for.

What is enforced, and by whom:

| Property | Enforced by | Holds against a hostile client? |
|---|---|---|
| Cannot act for a user who never called | the KDC (their ticket is the evidence) | yes |
| Cannot be pointed at a caller-supplied target | `delegation.TOOL_TARGETS`, keyed by tool name | yes |
| Cannot reach a target the realm has not approved | the KDC (`servicedelegationtarget`), which applies because a forwarded TGT is refused | yes |
| Cannot be handed the caller's full TGT | `delegation.is_narrow_evidence()` | yes |
| Off unless deliberately enabled | `MCP_DELEGATION` unset means no evidence is ever requested | yes |

The attack, and why it is now closed. A caller who sets `GSS_C_DELEG_FLAG`
hands this server their full forwarded TGT instead of a narrow evidence
credential. The realm's `servicedelegationtarget` allowlist does not constrain a
TGT, so using one would reach anything that caller could reach. Demonstrated on a
live KDC against `ldap@ipa`, which no rule permits:

    client does NOT delegate   ldap@ipa.example.internal  ->  refused
    CLIENT DELEGATES           ldap@ipa.example.internal  ->  ticket issued

`delegation.is_narrow_evidence()` refuses that credential, so the allowlist
applies to everything we actually use. The check reads MIT's
`GSS_KRB5_GET_CRED_IMPERSONATOR` (OID `1.2.840.113554.1.2.2.5.14`, MIT >= 1.16):
one buffer naming the impersonator for an S4U2Proxy evidence credential, an empty
set for anything else, a forwarded TGT included. It compares that name against
this acceptor's own principal, so a credential composed by some other service
does not pass either.

A hostile client cannot have it both ways. MIT sets that field in exactly one
place, `kg_compose_deleg_cred()`, on the accept path taken when the caller did
not set the flag, and sets it from the local acceptor's name. Nothing off the wire
reaches it, so it cannot be forged. Setting the flag routes MIT down
`krb5_rd_cred()` instead, which never sets it. The client's one lever picks the
branch, and the branch that would hand us the dangerous credential is exactly the
branch that loses the marker.

Verified on the live host, same caller both times, `GSS_C_DELEG_FLAG` the only
difference. The last column is the check bypassed, which is what shows it is
doing real work rather than agreeing with something else:

    non-delegating  narrow=True   trigger_build ALLOWED   bypassed ldap@ipa -> refused
    DELEGATING      narrow=False  trigger_build REFUSED   bypassed ldap@ipa -> TICKET ISSUED

Classification was stable over 200 iterations with no misclassification either
way, and costs ~0.1 ms in memory with no KDC round trip.

It fails closed. MIT older than 1.16, a python-gssapi without
`inquire_cred_by_oid`, a non-MIT mech, or any error returns `False`, which denies
forwarding. On such a platform [D1] does not work at all; that is intended,
because the alternative is forwarding credentials we cannot classify.

Ruled out as discriminators, so nobody re-derives them: `ctx.actual_flags` is
byte-identical in both cases (`delegate_to_peer` appears either way), as are
`cred.name`, `cred.usage` and `cred.mechs`; `cred.lifetime` differs only by
elapsed clock. "Is there a krbtgt in the exported ccache" fails too, because the
narrow case also has one, whose client is the service rather than the caller.
Two earlier probes concluded no discriminator existed by printing only the server
side with caller and service sharing a host.

`delegation.TOOL_TARGETS` is still the control a reviewer can read. Treat it
accordingly. It is security-owned, and
`tests/python/test_tool_policy_invariant.py` now enforces by AST inspection that
every `forward_header` call passes a literal tool name, that the literal is
the calling tool's own name, that a forwarding tool still calls `require()`
first, and that no target row names a tool which cannot forward. Those tests
were added when the KDC stopped counting as a second gate; a failure there is a
security regression, not a stale assertion to update.

What it does not mean. A hostile client gains no access it did not already
have: the onward ticket is issued *as that caller*, so it reaches only what they
could reach directly from their own machine with their own ticket. The server
lends no privilege. What changes is what the server holds, which is a [K1]
question, not a client-privilege question.

The shipped client never delegates ([CL1]), so this does not arise with the
software in this repo, and a modified one is now refused rather than trusted.
That property stopped
being incidental the moment `-Forwardable` existed: it is now the only thing
keeping our own users on the narrow side of the mechanism, so
`tests/python/test_mcp_krb_bridge.py::NeverDelegates` asserts both the bridge's
declared GSS init flags and the flags on the context it actually builds.

What the check does not do. It stops this server from using a forwarded TGT.
It does not stop a caller from sending one: MIT composes the credential during
accept, so the process holds it briefly before we refuse it. An attacker who
already has code execution here could harvest whatever a delegating caller sent,
which is a [K1] question and not one this check can answer. Our clients do not
delegate, so in practice there is nothing to harvest.

Cost, stated plainly. Enabling this narrows [C2]: the acceptor credential is
acquired `usage='both'`, so the keytab becomes usable for outbound authentication
and not only inbound. It also raises what a stolen keytab is worth, which
interacts with [K1] above: the prize grows from "be this service" to "be this
service, and act as any user who has called it, against the allowlisted targets".
[K1] was accepted against the smaller prize, so re-read it before enabling this.
The bound that remains is real: without protocol transition an attacker still
cannot synthesise a ticket for a user who never authenticated here.

Where targets come from, and why not only from code. The in-code
`TOOL_TARGETS` ships empty and a test keeps it that way, because a real
target is a real hostname and this repo has none. An operator names them in
`site.env` as `MCP_DELEGATION_TARGETS=tool=svc@fqdn[,...]`, which
`delegation._targets_from_env()` parses once at import and merges into
`TOOL_TARGETS` with `TOOL_TARGETS.update(...)`. So the effective policy at runtime
is the in-code rows plus the operator overlay, and [S2] describes it as the same
security-owned control seen from the authorization side.

That is deliberately the same trust level as `MCP_DELEGATION` itself: a
root-owned `EnvironmentFile` read by the systemd unit. The thing this file exists
to prevent is a caller-chosen target, and a caller cannot reach `site.env`;
neither can a tool author editing tool code. The overlay cannot override an
in-code row (a collision is fatal, not resolved by precedence, so a deployment
can never silently redirect a reviewed target), cannot name one tool twice, is
capped in entry count, rejects a non-FQDN or shell-metacharacter target, and
every parse failure raises at import so a typo stops the service instead of
leaving it serving a policy nobody read. `run.sh` validates the same grammar at
install time, plus that each named tool actually calls `forward_header`, so the
usual outcome is a message on the installer's terminal rather than a unit that
will not start.

One shipped tool forwards: `trigger_build`. It is the copy-me template for
forwarding tools and it is inert as shipped: with no `MCP_DELEGATION` and no
target it raises `no-target-policy` rather than falling back to the service
identity. Its HTTP call is left a stub on purpose: minting the ticket is the part
this repo owns and the part that is hard to get right, while the downstream REST
shape is site-specific, and a half-guessed request would be a worse starting
point than none.

Prerequisites, all outside this code:
- a FreeIPA `servicedelegationrule` binding `HTTP/<mcp-host>` to a target list
- the caller's ticket must be forwardable. Without protocol transition the KDC
  hard-requires it; a non-forwardable caller is refused with the same opaque
  `KDC_ERR_BADOPTION` as a missing rule, so check all three causes when diagnosing
- `MCP_DELEGATION=1` in the unit, plus a target per forwarding tool, either an
  in-code `TOOL_TARGETS` row or an `MCP_DELEGATION_TARGETS` entry in `site.env`.
  With the switch on and no target, every forward still fails closed; `verify.sh`
  check 14 reports that half-enabled state as information rather than showing a
  green tick on a feature that refuses every call it is asked to make
- workstations provisioned with `setup.ps1 -Forwardable`. The switch is off by
  default, so a fleet that does not forward keeps non-forwardable tickets and
  is structurally immune to the TGT-handover case above

Protocol transition (`ok_to_auth_as_delegate`) stays off permanently. It lets a
service mint a ticket as any user without them ever authenticating, turning a
keytab into an impersonation oracle. It is the variant the literature warns about;
constrained delegation *without* it is the recommended form and is what this is.

---

## LOW / operational (DEPLOYMENT)

- Clock skew: enrollment uses `--no-ntp`, so time sync is not guaranteed -
  verify `chronyc tracking` on every host (Kerberos rejects >5-min skew). [R1]
- DNS/SPN: reach the server by the A-record FQDN matching the SPN (a CNAME
  breaks ticketing); consistent forward+reverse DNS.
- Keytab rotation: `ipa-getkeytab` without `-r` bumps the KVNO and
  invalidates outstanding tickets - use `-r` to retrieve; rotate deliberately.
- SELinux (RHEL): `setsebool -P httpd_can_network_connect 1` for the nginx→app hop.
- `mkhomedir`: enroll runs `pam-auth-update --enable mkhomedir` (Ubuntu needs it).

---

## CVE inventory (consulted)

| CVE / advisory | Component | Applicability | Handling |
|---|---|---|---|
| CVE-2024-37370 / -37371 | MIT krb5 < 1.21.3 GSS token handling | the acceptor uses system GSSAPI | ⚙ keep MIT krb5 patched |
| CVE-2024-3183 | FreeIPA/MIT krb5 TGS session-key | KDC-side | ⚙ strong keys / patched IPA |
| CVE-2023-25563…67 | gss-ntlmssp | only if installed | ⚙ do not install it (krb5-only) |
| CVE-2025-33073 | Windows SMB reflective Kerberos relay | not applicable (Linux/HTTP) | N/A |

python-gssapi itself is a thin binding over system MIT krb5; keep the OS krb5
stack patched, that is where the
residual native risk lives. The MIT krb5 CVEs above are deployment/patch-level
concerns, not code changes in this tree.

---

## Deployment checklist (invariants the code depends on)

1. Explicit SPN in `MCP_SPN`, matching the keytab and DNS A record. [C1][C2]
2. Keytab custody. One contract, no alternatives. Any other value is what
   caused the first-boot outage (`MissingCredentialsError … Minor (13): Permission
   denied`). [K1]

   | Path | Owner | Mode |
   |---|---|---|
   | `/etc/mcp-server` | `root:<svcgroup>` | `0750` |
   | `/etc/mcp-server/krb5.keytab` | `root:<svcgroup>` | `0640` |

   `KRB5_KTNAME` is set in the systemd unit itself. The service user must be
   able to read the keytab - that is what the group-read bit is for. Note that
   `0640` with owner `root` means root reads it too; the mode restricts the
   world, not the superuser. Do not
   "harden" it to `0600` or to `root:root`; that breaks the acceptor with an error
   that names nothing useful. `server/install/verify.sh` asserts these (never
   chmods).
3. Replay cache on. Do not set `KRB5RCACHETYPE=none`; the bridge's per-request
   tokens mean there is nothing to gain by turning it off. [R1]
4. krb5-only (no gss-ntlmssp) as hygiene. [C1]
5. No `Authorization` header in any log/APM/SIEM. [R1]
6. Client distribution is an accepted risk, not a control. There is no signature
   on the client kit. Artifacts come over HTTPS from the publishing host, pinned to
   the realm CA on enrolled Linux and to an out-of-band `-CaSha256` on Windows, and
   a compromised publisher can serve anything to a root shell. So: guard the
   publishing host like the KDC, and if you need actual publisher-compromise
   protection, ship the client as a signed RPM from an internal dnf repo instead
   (strongest), or sign offline with a key that never touches the publisher. [SC1]
7. systemd sandbox active (incl. `MemoryDenyWriteExecute=yes`); app binds the UNIX socket. [K1][S1]
8. Authz groups resolve on the server host. `verify.sh` check 11 derives the
   group names from `authz.TOOL_GROUPS` (so it cannot drift from the policy) and fails
   naming any group SSSD does not resolve on that host. Create them in IPA as POSIX
   groups: a non-POSIX group has no gid, so it looks correct in the web UI and stays
   invisible to `getent`, which is the lookup that actually decides. Membership stays
   human, because membership *is* the authorization decision. Until the groups resolve,
   `authorize_tool()` fails closed and every non-open tool denies everyone while the
   deployment still looks healthy. [S2]
9. Keep MIT krb5 patched. [CVE]
10. Delegation stays off unless evidence-based S4U2Proxy is deliberately enabled;
    protocol transition (`ok_to_auth_as_delegate`) stays off permanently. [D1]
11. Server deps installed from `server/requirements.lock.txt` (fully `==`-pinned)
    via an internal mirror / wheelhouse / RPM - internal VMs may lack PyPI. The
    wheelhouse must carry every locked package, not just the two direct deps
    `mcp` and `uvicorn`; a mirror stocked from `requirements.txt` alone leaves the
    install to resolve transitive deps from an index that is not there. The venv
    must be created with `--system-site-packages`, because `python3-gssapi` is an OS
    package (from `ipa-client`) while `mcp` and `uvicorn` are pip-only: an isolated
    venv yields a server that starts and then fails every SPNEGO handshake. Verify
    `MemoryDenyWriteExecute=yes` starts with this stack. The bridge stays stdlib.
12. Tool/auth separation: the authorization policy and group lookup live in `server/authz.py` (security-owned, no SDK dep) - put that file under CODEOWNERS, along with `server/delegation.py` for the forwarding side. The invariant that every `@mcp.tool` calls `require()` with its own name and has a `TOOL_GROUPS` entry is enforced by `tests/python/test_tool_policy_invariant.py`, which runs in the standard suite (`sh tests/run-tests.sh`). It parses `mcp_server.py` instead of importing it, so it cannot skip on a host without the MCP SDK, and it checks the reverse direction too (no `TOOL_GROUPS` key without a tool behind it, since `authz_editor` derives its `known_tools` allowlist from that dict). Deny-by-default still backstops a missing entry; the test is what makes a missing `require()` loud.
13. Authz editor stays off unless deliberately enabled ([S4-EDITOR]). `server/authz_editor.py` is disabled by default (no `MCP_AUTHZ_EDITOR`, no dispatcher, no `/admin/*`). If enabled: set `MCP_POLICY_ADMINS` to an exact, tiny principal allowlist (not an IPA group, not `admin@REALM`); give the service a writable `StateDirectory` for the JSON overlay (keeps `ProtectSystem=strict` on the code); uncomment the nginx `location /admin/` block (needed so the app's nonce CSP applies); and put `authz_editor.py` + `MCP_POLICY_ADMINS` under CODEOWNERS. The reviewed in-code `TOOL_GROUPS` remains the fail-safe floor.

14. Windows workstations (`client/setup.ps1`): the kit installs a `wslssh` command and must not alias or replace `ssh` - hijacking `ssh` routes every connection through WSL, where the user's keys, host aliases, `known_hosts` and agent do not exist. The Kerberos ticket cache is a 0600 file cache under the WSL user's `~/.krb5/` (not `/tmp`, wiped on the frequent WSL VM restart; not `/var/tmp`, a 1777 directory where another uid can squat a predictable filename). Workstations are never enrolled in the realm - they only request tickets, so there is nothing to revoke server-side. Because WSL is not enrolled it has no realm CA, so `-CaSha256` is the out-of-band pin that makes the CA install verifiable, and it is now the only out-of-band trust root left in this path. [SC1] The `-Forwardable` switch is off by default and must stay off unless [D1] is deliberately in use. [CL1]

15. TLS certificates exist before nginx starts. The `listen 443` block names
    `{{CERTDIR}}/fullchain.pem` and `{{CERTDIR}}/privkey.pem`, so `nginx -t` fails
    hard if the files are absent - hence the two-phase bootstrap in the installer
    (HTTP-only vhost → issue → full vhost).

    `{{CERTDIR}}` is the directory, not the lineage name, and it is not reliably
    `/etc/letsencrypt/live/<fqdn>/`. The template says so in a comment for a
    reason: it is normally `/etc/letsencrypt/live/<MCP_CERT_NAME>/`, and
    `MCP_CERT_NAME` may differ from `MCP_HOST`. certbot also appends a `-0001` (then
    `-0002`, …) suffix to the lineage directory when a lineage of that name already
    exists, so the real path can be `/etc/letsencrypt/live/<name>-0001/`. And
    `--cert-mode existing --cert-path` points somewhere else entirely. Substituting
    the hostname alone here has already produced a vhost pointing at a directory
    nothing had ever written a certificate into. The path to use is the one the
    installer resolved, not one assumed from the FQDN.

    See the subsection below for the FreeIPA-specific issuance rules; they are not
    the public Let's Encrypt ones.

16. The entry points below are meant to be run rather than retyped. The deployment
    of this repo is two scripts and one manual step, each idempotent and safe to re-run:

    | Step | Command | Where |
    |---|---|---|
    | groups (once) | create each `authz.TOOL_GROUPS` name as a POSIX group | IPA web UI |
    | MCP host | `sudo sh server/install/run.sh --site-env /etc/mcp-server/site.env` | MCP host, already IPA-enrolled |
    | verify (closing item) | `sh server/install/verify.sh <fqdn>` | MCP host |

    `run.sh` restarts `mcp-server` unconditionally at the end of a run. It used
    to `systemctl enable --now`, which does nothing to an already-running unit and
    therefore left yesterday's process serving newly deployed code: unit active,
    every other check green, and the only symptom a newly added tool answering
    "Unknown tool". `verify.sh` check 13 catches that class directly by comparing
    the process start time against the mtime of the deployed code.

    Getting the `client/` scripts to the publisher is a plain file copy:
    there are no publish-time placeholders left in `client/`, so nothing has to be
    rendered, substituted or signed on the way.

    Who verifies it depends on which host serves it. By default the MCP host serves
    the bundle itself and `verify.sh` check 12 verifies it: it fetches the five files
    and the page and requires HTTP 200 unauthenticated, failing on a 401, because
    a machine being provisioned holds no ticket yet. With `--no-serve-client` a
    separate host serves an exported copy, it is outside this repo, and
    nothing here verifies what it serves. Either way [SC1] is
    the accepted risk: nothing signs those bytes, and whoever serves them runs
    code as root on every workstation that installs them.

    `verify.sh` runs 14 checks and is the last item of this checklist for a
    reason: every
    failure this review found was invisible to the operator - the ACME challenge
    401s while the cert still has 90 days, the policy denies everyone, the unit
    reports healthy while the acceptor rejects every handshake, the process serves
    code from last week. A broken install
    presents as a working one until a user hits it. The
    site values live in one file (`server/install/site.env.example` → `/etc/mcp-server/site.env`,
    gitignored); scripts hard-error on an empty required value rather than defaulting
    to a placeholder.

### TLS / private ACME (FreeIPA)

The issuer is the realm's own FreeIPA/Dogtag CA, not a public CA. Clients trust
it because `ipa-client-install` puts it in the trust store, which is also why no
client ever needs `-k` and no script may add one. Enable the responder once with
`ipa-acme-manage enable` on the IPA server; `ACME_DIRECTORY` in `site.env` points at
`https://<ipa-fqdn>/acme/directory`.

Three facts that cost real time to learn, recorded here so the next installer does
not rediscover them:

- `--key-type rsa` (with `--rsa-key-size 4096`) is mandatory. certbot 2.x
  defaults to ECDSA and the Dogtag ACME profile rejects it at finalize. The failure
  surfaces late, after the challenge has already validated, which makes it look like
  a server fault rather than a key-type mismatch.
- `certbot renew --dry-run` is a guaranteed false negative here. It forces the
  public Let's Encrypt *staging* endpoint, which rejects any `.internal` name with
  `rejectedIdentifier :: Domain name does not end with a valid public suffix (TLD)`.
  Do not read that as a broken renewal. Validate with `--dry-run --server
  "$ACME_DIRECTORY"`, or a one-time `--force-renewal` plus a certificate-serial diff.
- A reload on renewal is required. `certbot.timer` renews unattended,
  and without a hook nginx keeps serving the old certificate until a human reloads
  it. The installer passes `--deploy-hook 'systemctl reload nginx'` to `certbot certonly`,
  which certbot persists into the lineage's renewal conf as `renew_hook`. Verified by
  checking for that key, never by `renew --dry-run`, which forces the public staging
  endpoint and rejects `.internal` names outright.

One more, on the port-80 side: the ACME challenge location must be exempted from the
HTTPS redirect inside a `location` block, not left to a server-level `return`.
An MCP host that 308s `/.well-known/acme-challenge/` into the Kerberos-gated proxy
answers 401 to the CA, so issuance keeps working (the redirect did not exist at
first-run time) and the first *renewal* silently fails.

## Architecture note (Python + MCP SDK)

The server is the official MCP SDK (`mcp.server.fastmcp.FastMCP`, streamable HTTP)
wrapped by a self-contained SPNEGO ASGI middleware (`spnego_asgi.py`) that
reuses the KDC-proven acceptor (`spnego_auth.py`). The SDK owns the protocol; the
middleware owns security and runs before the MCP layer on every request. Tools are
`@mcp.tool()` functions that read the authenticated principal from the request
scope and never touch the acceptor, headers, or auth internals.

## The test suite

This section was `tests/TESTING.md`. It lives here now because a finding and the
test that proves it are the same subject, and splitting them meant the traceability
table drifted from the findings it pointed at.

### Three layers

Decreasing breadth, increasing fidelity:

| Layer | What | Where | Deps |
|---|---|---|---|
| Unit | control logic of the client bridge, the acceptor, the authz policy + editor, delegation, the server, and the tool→policy invariant | `tests/` - run `sh tests/run-tests.sh` | none (gssapi mocked) |
| Integration | real Kerberos: token mint, acceptor validation, replay rejection, full server flow | live on FreeIPA (the lab host), recorded under [Verified](#verified) | real KDC + keytab |
| Deployment | patch levels, krb5-only, keytab custody, TLS front | the [deployment checklist](#deployment-checklist-invariants-the-code-depends-on) and `verify.sh` | a real host |

### Running the unit tests

```sh
sh tests/run-tests.sh
# or, quietly, just the count and the result:
cd tests/python && python3 -m unittest discover -q
```

No test count is written down here, deliberately: a number pinned in prose goes
stale the moment a test is added or removed, and a stale count is worse than
none, because it invites a reader to trust it. Both forms above
print the number of tests they ran, and that printed number is the
authoritative one: a count written into prose goes stale the moment a test is added
or removed. If the two disagree, the runner is right and this line is the thing to
fix.

Hermetic: `tests/python/fake_gssapi.py` stands in for `python3-gssapi` (both the
initiator role for the client bridge and the acceptor role for the server), so the
suite runs anywhere with just `python3` (Windows, Linux, CI), no KDC.

### What is in each test file

- `test_mcp_krb_bridge.py` - the client (`client/bridge/mcp-krb-bridge.py`): the
  stdio↔HTTP framing, a fresh token per call, session/protocol header handling,
  and the [CL1] refusals (plaintext `http://` to a non-local host, no delegation).
- `test_spnego_asgi.py` - the ASGI middleware (`server/spnego_asgi.py`) that puts
  the acceptor in front of the app: 401 + `WWW-Authenticate: Negotiate` on no
  credentials, NTLM and incomplete-context rejection, principal onto the scope.
- `test_spnego_auth.py` - the acceptor (`server/spnego_auth.py`): [C1] completeness
  gate, mech pin, NTLM/oversize/garbage/malformed-principal rejection, explicit SPN.
- `test_authz.py` - the security-owned policy (`server/authz.py`) in isolation (no
  SDK): the connection gate (realm + lookalike-realm spoofing), the per-tool
  IPA-group allow/deny matrix incl. the allow path [S2], union semantics, deny-by-
  default, and the nss/SSSD lookup boundary (strict input, fail-closed, local-part).
- `test_mcp_server.py` - the server (`server/mcp_server.py`) driven over real HTTP:
  per-tool authz [S2] both deny and allow paths end-to-end, [C1] at the server level.
- `test_authz_editor.py` - the optional, disabled-by-default policy editor
  (`server/authz_editor.py`) + the `authz.py` overlay layer [S4-EDITOR]: the
  disabled-by-default / policy-admin-allowlist gate, ambient-credential CSRF
  defenses (Origin/Sec-Fetch/Content-Type), method + If-Match/ETag semantics,
  schema validation + fail-safe, merge-over-defaults, and the dispatcher's
  lifespan passthrough.
- `test_delegation.py` - on-behalf-of forwarding: off by default, target
  allowlist, evidence handling, and every fail-closed path. `OperatorTargetOverlay`
  covers `MCP_DELEGATION_TARGETS` parsing: malformed entries, non-FQDN and
  shell-metacharacter targets, duplicate tools, the entry cap, and the refusal to
  let a deployment redirect an in-code reviewed target. `ForwardedTgtIsRefused`
  and `NarrowEvidenceCheck` cover the finding-8 control: a caller who sets
  `GSS_C_DELEG_FLAG` hands over a full TGT and is refused, a caller who does not
  still works (so the check cannot be "fixed" by refusing everything), and every
  unresolvable case fails closed (no credential, another acceptor's stamp, no
  expected impersonator, an MIT too old to answer, the OID call raising). The
  fake models both credential kinds rather than only the narrow one, because a
  fake that always produced narrow evidence would let a regression that accepts
  TGTs pass green. [D1]
- `test_tool_policy_invariant.py` - AST invariants over `mcp_server.py`, covering
  authorization and forwarding in one file. It enforces checklist item 12 in the
  standard suite instead of by human review: it `ast.parse()`s
  `server/mcp_server.py` and asserts, for every `@mcp.tool`, that `require()` is the
  first statement after the docstring and names *that* tool, and that the tool has a
  `TOOL_GROUPS` entry; plus the reverse, that no `TOOL_GROUPS` key lacks a tool
  behind it (a stale key becomes an editable phantom tool in the optional editor's
  `known_tools` allowlist). On the forwarding side it asserts that a
  `forward_header` call must pass a literal tool name (never one computable from
  a request), that the literal must be the calling tool's own name, that a
  forwarding tool must still `require()` first, and that no `TOOL_TARGETS` row may
  name a tool that cannot forward. [D1]
  It parses rather than imports on purpose: importing `mcp_server` pulls in
  `mcp.server.fastmcp`, so an import-based check would *skip* on every box without
  the SDK, which is exactly where nobody is watching.

### Traceability (standard or finding to test)

| Ref | Requirement | Covered by |
|---|---|---|
| [C1] RFC 2743 GSS completeness | `test_spnego_auth`: *incomplete context rejected*, *non-krb5 mech rejected*, *NTLM rejected*; `test_mcp_server`: *incomplete/NTLM → 401*. Integration: valid tokens → principal on the lab host. |
| [C2] explicit SPN | `test_spnego_auth`: *requires explicit SPN*. |
| [C3] untrusted principal | `test_spnego_auth`: *malformed principal rejected*, *service principal accepted*. |
| [C4] no reflection | `test_mcp_server`: *NTLM 401 not reflected*. |
| [C6] bound work | `test_spnego_auth`: *oversize/garbage rejected*. |
| [S1] session ≠ bearer | Closed structurally, not behaviourally: the server runs `stateless_http=True`, so no `Mcp-Session-Id` is ever issued or honoured server-side and there is no session-binding behaviour to test. What is tested: `test_mcp_server`: *authenticated initialize*, *tool call sees principal* (each request independently authenticated by the ASGI middleware, the tool reading the per-request principal off the scope), *no auth → 401*, *NTLM → 401*. Client side, `test_mcp_krb_bridge`: *session and protocol headers*, *close sends DELETE with session*, *close is a no-op without session* - the bridge forwards a session id opaquely and never treats it as a credential. |
| [S2] per-tool IPA-group authz | `test_authz`: full allow/deny matrix (in-group allows, out-of-group denies, unknown tool denied, union, extra groups ignored, fail-closed lookup). `test_mcp_server`: deny and allow paths end-to-end through the SDK. `test_tool_policy_invariant`: every tool actually *reaches* that matrix (leading `require()` with its own name, policy entry present, no phantom entries). |
| [S4-EDITOR] optional policy editor | `test_authz_editor`: disabled-by-default gate, policy-admin allowlist (separate from the editable policy), CSRF (Origin/Sec-Fetch/Content-Type), If-Match/ETag 412/428, schema-validation + fail-safe-to-last-good, merge-over-defaults, dispatcher lifespan passthrough. |
| [D1] on-behalf-of forwarding | `test_delegation`: off by default, target allowlist, `MCP_DELEGATION_TARGETS` overlay parsing and its refusal to redirect an in-code row, and the finding-8 control (`ForwardedTgtIsRefused`, `NarrowEvidenceCheck`) with every unresolvable case failing closed. `test_tool_policy_invariant`: literal tool names at `forward_header`, `require()` first, no target row for a non-forwarding tool. `test_mcp_krb_bridge::NeverDelegates`: our own client stays on the narrow side. |
| [CL1] no plaintext / no delegation | client tests: *http:// refused* (to a non-local host; loopback is deliberately allowed and the token never leaves the machine), *fresh token per call*, and `NeverDelegates`: *declared init flags exclude delegation* and *the context actually built requests none*. The second is not redundant: the first would miss a flag added at the call site rather than to `_INIT_FLAGS`. This row previously claimed a delegation test that did not exist; it was written when `-Forwardable` made the property load-bearing rather than incidental. |
| [SC1] client distribution | No test, because there is no control here to test. The client kit is unsigned by design; what protects it is HTTPS plus a CA pin, and both are properties of the transport and the operator's deployment rather than of code in this tree. [SC1] is an accepted risk, not a passing check: the finding carries the detail, rather than this row. |
| [NG1] nginx hardening | No unit test: it is a config, verified on the host. `verify.sh` checks 6, 9, 10 and 12 cover the ACME exemption, the unauthenticated challenge, the authenticated round trip and the client files. The open item (missing security headers on the client-distribution block) is not caught by anything automated; see the finding. |
| RFC 4559 §4 Negotiate challenge/header | `test_mcp_server`: *401 + WWW-Authenticate*; `test_mcp_krb_bridge`: *Authorization header is a `Negotiate ` token*. |
| RFC 4120 §3.2.3 replay MUST | Integration only (needs a real rcache) - proven live "Request is a replay". Not unit-testable with a mock. |
| RFC 5929/9266 channel binding | Not implemented [CB1]; not unit-testable. |

CVE traceability is the [CVE inventory](#cve-inventory-consulted) above. The
acceptor-completeness bypass ([C1], no CVE) is structurally impossible here, and
the only native dependency is the system MIT krb5 stack, tracked in that table.

### Honest limits

The mock acceptor can't reproduce a real replay cache, clock-skew rejection, or an
actual NTLM negotiation - those are integration/deployment (replay proven live;
NTLM prevented by krb5-only). These are tests of *our* code, not an audit of
python-gssapi or the system MIT krb5.

Session-binding behaviour is untestable because no session exists - see the
[S1] row above. The absence of those tests reflects the control working rather
than a coverage gap.

`test_tool_policy_invariant.py` reads the source of `mcp_server.py`, so it proves
the *shape* of the gate, not that the gate denies at runtime - the runtime proof is
`test_authz` plus `test_mcp_server`. The two are complementary: one asserts that
every tool is wired to the policy, the other that the policy decides correctly.

The delegation tests exercise `is_narrow_evidence()` against a fake that models both
credential kinds, which proves the branching logic. It does not prove that MIT
krb5 really sets `GSS_KRB5_GET_CRED_IMPERSONATOR` where [D1] says it does. That part
is a live-KDC result, recorded in [D1], and it is the reason the finding shows the
measured output rather than only the argument.

## Verified

- Hermetic unit tests (`sh tests/run-tests.sh` - fake gssapi, no KDC): all
  passing. The runner prints the live count; no number is pinned here.
  They cover the client bridge, the acceptor
  (`spnego_auth`), the ASGI auth middleware (`spnego_asgi`), the authz policy and
  the optional editor, delegation ([D1], including the forwarded-TGT refusal), the
  tool→policy invariant (checklist item 12), and an SDK
  integration smoke test (skips if `mcp` absent) confirming a `tools/call` in
  stateless mode returns the per-request principal.
- Live on real FreeIPA (the lab host): the acceptor (`spnego_auth`, 6/6) against a
  real KDC, incl. real token validation and replay rejection. The acceptor is
  the Kerberos-critical code and is unchanged, so the SDK migration didn't
  disturb it. Also live: the [D1] narrow-evidence classification, both branches,
  200 iterations, no misclassification.
- Not exercised on the real KDC: the full SDK server (the SDK could not be
  pip-installed on the lab host - internal PyPI gap), real nginx front,
  an actual Claude Code session, and the privileged-tool allow path - all
  deployment-time. The SDK integration is proven hermetically.
