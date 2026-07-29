# Reference Implementation of a Kerberised MCP Server and VS Code Remote-SSH for multi-OS FreeIPA Environments

> Kerberos single sign-on for MCP against FreeIPA: authenticate with the ticket a developer already holds from logging in, authorize by directory group, and keep no passwords, API keys or per-developer secrets anywhere.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![tests](https://github.com/overpassconnect/mcp-krb-server/actions/workflows/tests.yml/badge.svg)](https://github.com/overpassconnect/mcp-krb-server/actions/workflows/tests.yml)

## What it is

MCP has no enterprise single-sign-on story. Claude Code's MCP client can attach an
OAuth flow or a fixed header to its requests, but it cannot speak HTTP
Negotiate/SPNEGO, the standard way a browser or a command-line tool proves a Kerberos
identity to a web service. So it cannot authenticate directly to a Kerberized
internal MCP server. This repository is a worked, reviewed answer for FreeIPA shops:
it closes that gap using the Kerberos ticket a developer already holds from logging
in to a FreeIPA-enrolled machine. No passwords, no API keys, no per-dev secrets.

It is a reference implementation. The MCP tools it ships (`whoami`,
`list_projects`, `restart_service`, `trigger_build`) are stubs; the value is the
authentication, authorization, delegation and deployment scaffolding around them,
meant to be read, reviewed and adapted to your own tools. Your own tools go in a
separate file that this repository never carries, loaded through `MCP_SITE_TOOLS`
(see [Configuration](#configuration)), so a deployment does not end up
maintaining a fork of a file it did not write.

A tool can also act on behalf of the caller. One of those stubs, `trigger_build`,
shows the delegation path: a tool calls a downstream Kerberized service as the human
who invoked it, so the downstream logs the real person rather than a shared service
account. It is off by default, reaches any Kerberized service (CI is only the
example), and has the one genuinely subtle security story here. Its own section,
[On-behalf-of delegation](#on-behalf-of-delegation), covers it.

## What it looks like

A developer logs in to their workstation. That is the only time anyone types a
password. From then on Claude Code reaches the internal MCP server with no further
prompt and nothing to configure:

```sh
klist              # a ticket is already there, put in place at login
claude mcp list    # internal-tools: connected
```

The server learns who they are on every request, decides what they may call from
their directory group membership, and records the decision under their real name.
Because nothing was set up with a shared secret, there is nothing to rotate, leak,
or hunt down later: removing the account in FreeIPA removes the access.

## Quick start

### Build the MCP host

`server/install/run.sh` is the installer, and it covers every step so nothing has
to be done by hand: the service account, the `--system-site-packages` venv, the
code deploy, the keytab retrieval and permission contract, `mcp-server.service`,
the nginx vhost, the certificate, and the certbot deploy hook. It is idempotent, so
re-running it converges, and it refuses to proceed on a value it cannot resolve
rather than defaulting to a placeholder.

Two prerequisites are human on purpose, because they consume admin credentials the
installer deliberately refuses to hold (it preflights for both and stops with the
exact command if either is missing):

1. The host is enrolled in FreeIPA (`ipa host-add` with a one-time OTP, then
   `ipa-client-install` on the box).
2. The IPA service principal `HTTP/<mcp-fqdn>` exists and this host is allowed to
   retrieve its keytab. `run.sh --create-ipa-service` will do this for you, but
   only if you already hold an admin ticket.

Then, with `server/install/site.env.example` copied to `/etc/mcp-server/site.env`
and filled in:

```sh
sudo sh server/install/run.sh --site-env /etc/mcp-server/site.env
sh server/install/verify.sh <fqdn>
```

The server's Python environment is the one part worth understanding before you run
it. The venv must be created with `--system-site-packages` so it keeps the OS
`python3-gssapi`, with `mcp` and `uvicorn` installed from
`server/requirements.lock.txt`. An isolated venv produces a server that starts
cleanly and then fails every SPNEGO handshake. The installer gets this right; the
note is here for anyone building the environment by hand.

Two warnings that bite in practice:

- The installer runs as root and deploys whatever it finds in the source tree, so
  it walks every parent directory up to `/` and refuses a checkout that is not
  root-owned or is group/world-writable. A `git pull` into a home directory fails
  this by design; copy the tree to a root-owned path first.
- `run.sh` restarts `mcp-server` unconditionally at the end, because `systemctl
  enable --now` does nothing to an already-running unit and would otherwise leave
  yesterday's process serving new code with every check still green.

`verify.sh` is read-only and worth re-running after any change: 14 checks that turn
a silently broken install (a 401ing ACME challenge, a policy that denies everyone, a
stale process, a delegation flag half-configured) into a loud one. Full installer
detail, what `verify.sh` asserts, and what the host serves live in
[`server/`](server/) and [SECURITY.md](SECURITY.md).

### Provision a workstation

One command per platform, documented end to end in
[`client/README.md`](client/README.md): `client/setup.sh` for IPA-enrolled Linux,
`client/setup.ps1` for non-domain-joined Windows (it stands up Kerberos SSH and the
bridge inside WSL2, where the ticket lives). Both fetch the kit over HTTPS pinned to
the realm CA and never pipe a download to a shell.

macOS has no script. It is a short, documented manual Kerberos-client setup
(see [`client/README.md`](client/README.md) and the provisioning page the MCP host
serves), separate because macOS ships Heimdal rather than MIT krb5 and needs a
specific `kdc = tcp/...` line that a naive config gets wrong.

Shared team workspace: once users reach a host with their own Kerberos identity, a
directory the whole team can edit needs no extra machinery. FreeIPA already puts
everyone in the `ipausers` group, so one owned `root:ipausers` at mode `2770` (setgid)
with a default ACL (`setfacl -d -m g:ipausers:rwx`) is group-writable, and new files
inherit both the group and the writability. Keep it under `/srv` rather than
`/home/<name>` (IPA auto-creates home directories there), and keep secrets out of a
group-writable path.

## What you get

- One password, typed at login, and nothing stored anywhere afterwards. No API key
  to leak, rotate, or discover in a config file two years later. Disable the account
  in FreeIPA and the last service ticket dies within hours by its own validity
  window.
- Every request is authenticated on its own, offline, against the keytab. A
  half-finished handshake is never mistaken for a completed one, which is the bug
  class behind NTLM-style pre-auth bypasses (`[C1]`: the acceptor gates on
  `ctx.complete`, true GSS completeness per RFC 2743).
- No session to steal. The server runs `stateless_http=True`, so no `Mcp-Session-Id`
  is ever issued or honoured as a bearer credential (`[S1]`).
- Authorization is deny by default, per tool, by IPA group, resolved through SSSD's
  local cache with no network call on the request path (`[S2]`).
- Who may call what is code rather than configuration: `authz.TOOL_GROUPS` and
  `delegation.TOOL_TARGETS` live in security-owned files, so changing them is a
  reviewed change. A bounded operator overlay (`MCP_DELEGATION_TARGETS`) exists for
  site-specific targets, syntax-checked, capped, and unable to override a reviewed
  one.
- The replay cache stays on, the service runs under a full systemd sandbox including
  `MemoryDenyWriteExecute`, and the only long-lived secret is a keytab readable by
  the service account and root (`[R1]`, `[K1]`, an accepted residual documented in
  SECURITY.md).
- A tool can act as the caller against any Kerberized downstream service, off by
  default (`[D1]`). An earlier finding, that a client could forward a full TGT to
  escape the target allowlist, is closed by a runtime check; see
  [On-behalf-of delegation](#on-behalf-of-delegation).

## How it works

The client is a small local stdio bridge ([`client/bridge/`](client/bridge/)):
Claude Code runs it as a subprocess and it forwards every JSON-RPC message to the
server, normally over HTTPS with a freshly minted `Negotiate` token. Two exceptions
are deliberate: the bridge accepts `http://` only for `localhost`, `127.0.0.1` and
`::1` and refuses any other scheme, and `MCP_KRB_NOAUTH=1` drops the `Authorization`
header for local testing. Both let a developer exercise the transport without a KDC,
and neither belongs in a deployed config.

Server and bridge are both Python. The bridge is stdlib only: `python3-gssapi`
ships with `ipa-client`, so there is nothing to `pip install` on an IPA-enrolled
Linux workstation. (Inside WSL the distro is not enrolled and has no `ipa-client`,
so `python3-gssapi` and `krb5-user` are an explicit `apt install`, which `setup.ps1`
performs.)

The server is the official MCP Python SDK (FastMCP, streamable HTTP) with the
Kerberos auth as a self-contained ASGI middleware in front, behind nginx (TLS).
Non-domain-joined Windows workstations need one extra step, covered under
[Provision a workstation](#provision-a-workstation) above.

```
 One tool call, end to end.  Every arrow carries [T] the transport and [A] what authenticates it.
 Three arrows say [A] none. Those are deliberate, and each one is explained below the diagram.

 WORKSTATION (IPA-enrolled)          | NETWORK |   MCP HOST mcp.example.internal    | REALM
 ------------------------------------+---------+-----------------------------------+-------------
                                     |         |                                   |
  [ Claude Code ]                    |         |                                   |
        |                            |         |                                   |
        | (1) [T] stdio pipes, one JSON-RPC message per line                        |
        |     [A] none: the OS process boundary. The bridge runs as you, with       |
        |         your ticket. This hop adds no authentication of its own.          |
        v                            |         |                                   |
  [ mcp-krb-bridge.py ]              |         |                                   |
        |     \                      |         |                                   |
        |      \ (2) [T] Kerberos TGS-REQ, SPNEGO mech 1.3.6.1.5.5.2 ------------> [ FreeIPA KDC ]
        |       \    [A] your TGT, put in your ccache by SSSD when you logged in.  |  ipa.example
        |        \       The bridge never prompts for a password.                  |  .internal
        |         \  Flags asked for: mutual_auth, out_of_sequence.                |       |
        |          \ never delegate_to_peer. See [CL1].                            |       |
        |           \                 |         |                                  |       |
        |            <---- service ticket for HTTP/mcp.example.internal -----------+-------+
        |                             |         |                                   |
        | (3) [T] HTTPS 443, TLS 1.2+, realm CA. New token every request.           |
        |     [A] Authorization: Negotiate <base64 AP-REQ>   (RFC 4559)             |
        +---------------------------->|-------->[ nginx ]                           |
                                      |         |   TLS terminates here. Rate + conn
                                      |         |   limits, 1 MB body cap, X-Forwarded-For
                                      |         |   overwritten, security headers.
                                      |         |        |
                                      |         | (4) [T] UNIX socket /run/mcp-server/mcp.sock,
                                      |         |         root:<nginx-group> 0660, parent dir 0755
                                      |         |     [A] none: file permissions are the control.
                                      |         |         0666 here would let any local user bypass
                                      |         |         nginx entirely. Set by ExecStartPost as
                                      |         |         root, because the sandboxed service holds
                                      |         |         no CAP_CHOWN and cannot set it itself.
                                      |         |        v
                                      |         |   [ uvicorn ]
                                      |         |        |
                                      |         | ===== Gate 1: who are you =====================
                                      |         |   SpnegoAuthMiddleware + spnego_auth
                                      |         |     reject NTLM, cap token at 64 KB
                                      |         |     accept using KRB5_KTNAME's keytab
                                      |         |       (that file is root:<grp> 0640)
                                      |         |     require ctx.complete <- the real gate [C1]
                                      |         |     pin mech to krb5/SPNEGO, regex the principal
                                      |         |     require the realm to match MCP_REALM
                                      |         |   fail -> 401 Negotiate / 403. Reason to the audit
                                      |         |   log only, never to the caller. [C4]
                                      |         |        |
                                      |         |   pass -> scope['krb_principal'] = alice@...
                                      |         |        v
                                      |         | ===== Gate 2: may you do this =================
                                      |         |   require(ctx, '<this tool's own literal name>')
                                      |         |     authz.TOOL_GROUPS[tool] -> IPA group set
                                      |         |     os.getgrouplist via SSSD's local cache
                                      |         |     no network. Any error -> deny. [S2]
                                      |         |        |
                                      |         |   every decision, allow or deny, -> JSON audit
                                      |         |   line on stderr -> journald
                                      |         |        v
                                      |         |   [ the tool runs ]
                                      |         |        :
                                      |         :        : (5) optional, off by default. [D1]
                                      |         :        : forward_header(ctx, '<own name>')
                                      |         :        :   is_narrow_evidence()? a forwarded TGT
                                      |         :        :     is refused here
                                      |         :        :   TOOL_TARGETS[tool] -> exactly one SPN
                                      |         :        :   [T] S4U2Proxy TGS-REQ ------> [ KDC ]
                                      |         :        :   [A] the evidence credential naming you
                                      |         :        v
                                      |         :   [ downstream ] sees alice, not the MCP
                                      |         :   service account. Site supplies the HTTP call.
```

The bridge turns each MCP message into an HTTPS request carrying a fresh SPNEGO
token, which nginx terminates and hands to the Python server over a UNIX socket.
Gate 1 (`spnego_asgi.py` with `spnego_auth.py`) validates the ticket offline against
the keytab and answers who the caller is [C1]. Gate 2 (`authz.py`, the first line of
each tool) answers whether that caller may call the tool, deny-by-default by IPA
group [S2]. The three `[A] none` arrows are hops a stronger control already covers,
the OS process boundary and the UNIX socket permissions. Delegation (arrow 5) is off
by default. [SECURITY.md](SECURITY.md) is the reference for all of it.

## On-behalf-of delegation

Off by default. A tool can call a downstream Kerberized service as the caller, so
the downstream sees the real human rather than this server's shared service account.
The shipped example `trigger_build` forwards to a CI system, but the mechanism knows
nothing about CI: it reaches any Kerberized service the caller could reach, such as
an internal REST API, a directory, a database proxy, or a second MCP server.

The mechanism is evidence-based S4U2Proxy constrained delegation. It does not use
protocol transition, the variant that would let a service mint a ticket for a user
who never authenticated. When the caller authenticates, MIT composes a credential
naming them from the ticket they already presented; the server shows that to the KDC
and asks for a ticket to one named downstream service. Two limits follow: it cannot
act for a user who never called, since that user's ticket is the evidence, and it
cannot reach a service `delegation.TOOL_TARGETS` has not named (deny by default, one
target per tool, security-owned in code plus a bounded operator overlay).

The subtle part, and the reason this is more than a config switch, is that a
hostile client can set `GSS_C_DELEG_FLAG` and hand the server its full forwarded TGT
in place of a narrow evidence credential, which the realm's target allowlist does
not constrain. The server rejects that credential. `is_narrow_evidence()` reads
MIT's `GSS_KRB5_GET_CRED_IMPERSONATOR`, a marker the Kerberos library writes only on
the non-delegating accept path and from the server's own name, so a client cannot
forge it, and it accepts only an S4U2Proxy evidence credential composed by this
acceptor. It fails closed on every unresolvable case, including a GSSAPI too old to
answer the question. So an earlier finding, that a client could forward a TGT to
escape the allowlist, is closed by that runtime check, and the realm's allowlist
holds for everything the server uses.

Enabling it has a cost the docs spell out: the acceptor credential becomes usable
for outbound authentication, which raises what a stolen keytab is worth under [K1].
Turning it on is a deliberate deployment decision. The shipped client does not
delegate ([CL1]), and the full analysis is [D1] in [SECURITY.md](SECURITY.md).

## Configuration

`server/install/site.env.example` is the single source of site values (domain,
realm, KDC, MCP URL, CA hash, delegation toggles). Copy it to
`/etc/mcp-server/site.env`, fill it in, and keep it out of git; the installer reads
site values from there and nowhere else.

### Your own tools

`MCP_SITE_TOOLS` points at a Python file loaded at startup, after the shipped
stubs and before the ASGI app is built. It defines one function:

```python
def register(mcp, require, forward_header, register_tool_policy):
    @mcp.tool()
    def list_tickets(ctx: Context) -> str:
        """List the caller's tickets."""
        p = require(ctx, 'list_tickets')          # authorize first, always
        h = forward_header(ctx, 'list_tickets')   # optional: act as the caller
        ...
    register_tool_policy('list_tickets', {'support-staff'})
```

Keep that file outside the deployed code directory. `run.sh` converges that
directory on this repository's file set, so anything left beside the shipped
modules is removed on the next deploy, and your tools would go with it.
`/etc/mcp-server/site_tools.py` is the natural home: the installer owns that
directory and never prunes it. Own it `root:root 0644`, the same as the code, and
keep it in whatever repository holds your site configuration.

Loading is fail-loud. A path that is set but unreadable, unloadable, or missing
`register()` stops the server at startup rather than quietly serving a tool set
that lost half its entries. Two limits worth knowing: the invariant test in
`tests/python/` parses `mcp_server.py` only, so it does not check a site tool's
`require()` wiring, and delegation targets for site tools still come from
`MCP_DELEGATION_TARGETS` like any other.

## Repository layout

```
server/          # the MCP server (official SDK)
  spnego_auth.py     - hardened Kerberos acceptor (fixes [C1] by construction)
  spnego_asgi.py     - self-contained SPNEGO ASGI auth middleware (wraps the SDK app)
  mcp_server.py      - FastMCP server (stateless) + tools; wires in authz + audit
  authz.py           - security-owned per-tool IPA-group policy + SSSD group lookup
  authz_editor.py    - optional, disabled-by-default browser editor for that policy
  delegation.py      - security-owned on-behalf-of forwarding policy; off by default
  requirements.txt   - server-only deps (mcp, uvicorn); the bridge stays stdlib
  requirements.lock.txt - the ==-pinned tree actually validated; install from this
  install/           # everything about getting it running, kept apart from what runs
    run.sh  - the installer: account, venv, code, keytab, unit, vhost, cert, and
              the client bundle (served at /client/ by default, or --client-export DIR)
    verify.sh  - read-only post-install verifier (last step of the install), 14 checks
    site.env.example   - the single source of site values; copy, fill, keep out of git
    mcp-server.service, nginx-mcp.nginx
client/          # everything that runs on a workstation
  setup.sh           - Linux: enroll in FreeIPA, then install the MCP client
  setup.ps1          - Windows: WSL2 Kerberos SSH + optional MCP bridge
  install-bridge.sh         - install the client (downloaded over HTTPS, then run; never piped to a shell)
  JsoncEdit.ps1      - helper used by setup.ps1 to edit JSONC config in place
  README.md          - provisioning a Linux or Windows workstation, end to end
  bridge/            # the MCP client Claude Code runs; what install-bridge.sh installs
    mcp-krb-bridge.py  - the bridge itself (stdlib + python3-gssapi)
    examples/          - mcp.json, mcp.json.windows, managed-mcp.json
tests/           # hermetic unit tests (fake gssapi, no KDC needed)
  run-tests.sh, python/
```

The installer directory is `server/install/`. If you find a doc or a script
referring to `server/deploy/`, it is stale.

## Security

The full threat model, RFC compliance mapping, ranked findings, CVE inventory and
deployment checklist live in [SECURITY.md](SECURITY.md). Read it before deploying.

Headline posture: authentication is offline SPNEGO/Kerberos on every request, the
replay cache stays on, authorization is per-tool deny-by-default by IPA group, and
the only long-lived secret is a keytab readable by the service account and by root.
The finding to read before deploying is [SC1], which is not fixed: client
distribution rests on HTTPS plus a CA pin with no signature, so a compromised
publisher can serve anything, and whoever controls those bytes runs code as root on
every workstation that installs them. It is an accepted risk with a named upgrade
path, and the docs treat it as accepted rather than solved.

## Documentation

- [SECURITY.md](SECURITY.md): the security review. RFC compliance mapping,
  ranked findings, CVE inventory, and the deployment checklist. Read before
  production.
- [client/README.md](client/README.md): provisioning a Linux, Windows, or macOS
  workstation end to end, including non-domain-joined Windows via WSL2 (Kerberos SSH
  + VS Code) and the trust model for the client kit.

## Contributing

Run the hermetic unit tests with `sh tests/run-tests.sh`: they pass on Windows and
Linux with no native packages, no KDC and no MCP SDK, using a fake `gssapi`, and
include a source-level check that every `@mcp.tool` is wired to the authorization
policy and that a tool which forwards names itself. Security-owned paths (the
acceptor, the middleware, `authz.py`, `delegation.py`) require review under
[.github/CODEOWNERS](.github/CODEOWNERS); a fork should point that file at its own
reviewers. Report vulnerabilities per
[SECURITY.md](SECURITY.md#reporting-a-vulnerability), not in a public issue.

## License

[Apache-2.0](LICENSE), copyright Overpass Connect. See [NOTICE](NOTICE).
