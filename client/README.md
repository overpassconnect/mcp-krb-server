# Client setup

Everything a workstation or server needs to talk to the Kerberized MCP server,
plus (on Windows) passwordless SSH and VS Code Remote-SSH against FreeIPA hosts.

## Where the files come from

These files have to be served over HTTPS so a workstation can bootstrap. Serving
them is a role that any host can fill: by default the MCP host fills it at
`https://mcp.example.internal/client`, and an exported copy can be served from
anywhere.

| File | What | Fetched by |
|---|---|---|
| `setup.sh` | Linux: enrol in FreeIPA, then install the MCP client | a human |
| `setup.ps1` | Windows: WSL2 Kerberos SSH, VS Code Remote-SSH, Firefox-in-WSL, and the MCP bridge | a human, or MDM |
| `install-bridge.sh` | install the MCP bridge only | `setup.sh`, `setup.ps1`, or a human |
| `JsoncEdit.ps1` | helper used by `setup.ps1` | `setup.ps1` |
| `mcp-krb-bridge.py` | the bridge itself | `install-bridge.sh` |
| `mcp-krb-remote-bridge.py` | the half that holds nothing, for a host with no ticket | `install-bridge.sh` |
| `mcp-fetch` | fetch one URL byte-exact; picks between the two above | `install-bridge.sh` |

### The MCP host serves them

One box, two roles. A normal install sets up the vhost and lays the files down:

```sh
sudo sh server/install/run.sh --site-env /etc/mcp-server/site.env
```

Workstations then use `--base-url https://mcp.example.internal/client`. The path
is configurable via `CLIENT_PATH` and defaults to `/client/`.

The location is static and unauthenticated, which is required here: nginx does not
gate the API (the SPNEGO check is in the application), and a machine being
provisioned has no ticket yet, so anything it must fetch in order to get one cannot
demand one. `verify.sh` check 12 treats a 401 here as a failure.

Open item, not yet fixed: the generated client-distribution `location` block does
not inherit the vhost's security headers. `add_header` is not inherited into a
location that declares its own, so the hardening applied to the API surface stops
at this block. See [NG1] in [SECURITY.md](../SECURITY.md).

### Serving an exported bundle elsewhere

You do not have to serve the bundle from the MCP host. Add `--client-export DIR`
to the installer and it also writes the complete bundle (the client files, the
provisioning page, and a generated `config.js`) into `DIR`:

```sh
sudo sh server/install/run.sh --client-export /var/www/client-bundle
```

Add `--no-serve-client` too if you do not want this host to serve it as well.
Copying that directory off to whatever host will serve it is your own job, with
your own tools. It is byte for byte what the MCP host serves, and the page reads
its own download URL from wherever it ends up, so there is nothing per-host to
configure. Point `--base-url` at that host.

### Either way

A plain copy is the whole job. There are no placeholders left in `client/` to
substitute, nothing to render, nothing to sign. (The `{{TOKEN}}` placeholders that
remain live in `server/install/` and are resolved on the MCP host at install time,
which is unrelated.)

Two obligations this repo cannot enforce: serve over HTTPS with a certificate that
chains to the realm CA, or the client-side pin never engages; and guard write
access to that directory as carefully as the KDC, because whatever sits there runs
as root on every workstation.

Two different URLs are involved on every path, and conflating them is the classic
mistake:

- the download base (`--base-url` / `-BaseUrl`) is where the bytes come from: the
  MCP host by default, or whatever host serves an exported bundle;
- the MCP URL (`--mcp-url` / `-McpUrl`) is what the installed bridge talks to, and
  nothing is ever downloaded from that API endpoint. By default the same host also
  publishes the kit at `CLIENT_PATH`, which is a different URL on the same machine
  from the API endpoint.

Neither has a default. A machine told to install the bridge and not told where to
fetch it from is an operator error knowable from the command line, so it is
refused before anything is mutated.

## Trust model

This is transport security only. There is no signature on anything here, and that
is deliberate. The honest summary is short.

Artifacts are fetched over HTTPS from the publisher, and the scripts never pipe a
download to a shell: `install-bridge.sh` is written to a file and then executed.
The TLS leg is narrowed where it can be:

| Platform | What pins the TLS leg |
|---|---|
| Linux, already enrolled | the realm CA at `/etc/ipa/ca.crt`, which `ipa-client-install` put there |
| Windows (WSL) | the realm CA is installed by the script into WSL's trust store and pinned by SHA-256 via `-CaSha256`, delivered out of band |

WSL is never enrolled in the realm, so it starts with no realm CA at all. That is
why the Windows path needs the hash and the Linux path does not, and it is why
`-CaSha256` is the only value you still have to deliver out of band.

`-CaSha256` is the only value here that is not simply trusted from the host serving
the files. `JsoncEdit.ps1` is fetched on plain TLS, the same trust
`install-bridge.sh` gets before running as root.

What this does not defend against, stated plainly: a compromised publisher can
serve anything. It serves `install-bridge.sh`, which runs as root. Nothing on the
client side would notice. The clients confirm they reached the host they were told
to reach and nothing about what that host chose to send. Beyond that, we hope the
publishing host is not compromised. By default that host is the MCP host itself, so
the exposure is shared rather than reduced.

A signature whose key lives on the serving host would defend against nothing the
transport already covers, since a compromised publisher holds the key, and it
would cost a verifier on every client plus a key to distribute. Real protection
needs the key somewhere that host cannot reach: sign offline, or ship the client
as a signed RPM in an internal dnf repo via the base image (strongest). See
[SECURITY.md](../SECURITY.md) [SC1].

## Linux

### `setup.sh` - enrol and install

For a new machine. It enrols in FreeIPA and then installs the MCP client, in one
command. Arguments it does not recognise are passed through to
`ipa-client-install` unchanged, with the company-standard `--mkhomedir` and
`--no-ntp` added if omitted.

```sh
# on the IPA server
ipa host-add newbox.example.internal --random        # prints an OTP

# on the new machine
curl --proto '=https' --tlsv1.2 -fsS \
    https://mcp.example.internal/client/setup.sh -o /tmp/s.sh
sh /tmp/s.sh \
    --base-url https://mcp.example.internal/client \
    --mcp-url  https://mcp.example.internal/ \
    --hostname=newbox.example.internal \
    --server=ipa.example.internal --domain=example.internal \
    --realm=EXAMPLE.INTERNAL --password='<OTP>' --unattended
```

Those `https://mcp.example.internal/client/...` URLs are the default: the MCP host
serves the kit at `/client`. If you exported the bundle and serve it from another
host, only the download base changes, so point `--base-url` at that host and fetch
`setup.sh` from the same place.

`--proto '=https'` matters. Without it a redirect can downgrade the fetch to
plaintext, and what comes down that wire is executed as root a moment later. `-o`
then `sh` rather than a pipe, for the same reason: a truncated download that is
piped straight to a shell has already run half of itself.

`--skip-mcp` enrols in IPA only. That is the supported way to defer the MCP
client to a later run. Idempotent: an already-enrolled host skips
`ipa-client-install`, and re-running replaces a stale shim.

Enrolment runs first, so by the time anything is downloaded the machine has
`/etc/ipa/ca.crt` and the download leg is pinned to the realm CA. If the
publisher's certificate does not chain to it, the fetch says so and falls back to
the system trust store. That warning matters: with the pin gone that leg rests on
public-CA TLS alone, and there is no second check behind it. A publisher whose
certificate is issued by the realm CA is the configuration this is written for. With the MCP host serving the kit that is automatic: the MCP host's certificate comes from the
realm CA through FreeIPA's ACME service, so an enrolled machine fetching
`install-bridge.sh` from it validates against the pin and never reaches the fallback.

### `install-bridge.sh` - install only

For a machine that is already IPA-enrolled. Same transport, no enrolment.

```sh
curl --proto '=https' --tlsv1.2 -fsS \
    https://mcp.example.internal/client/install-bridge.sh -o /tmp/i.sh
sh /tmp/i.sh \
    --base-url https://mcp.example.internal/client \
    --mcp-url  https://mcp.example.internal/ \
    --managed
```

The bridge lands in `/opt/mcp-krb`. `--managed` registers the server fleet-wide
in `/etc/claude-code/managed-mcp.json`; without it the script prints the
`claude mcp add` command and changes no configuration.

`setup.sh` downloads and runs this script for you.

Prefer a signed RPM in an internal dnf repo over curl-at-enrolment where you can
(SECURITY.md [SC1]): it is the one option that moves the trust root off the
publishing host. This is the download-then-run fallback for sites that have no internal
repo.

## Windows

### Admin: once per machine

```powershell
.\setup.ps1 -IpaUser jdoe
```

Idempotent, takes about a second, no admin rights needed if WSL2 already exists.
Other realms: `-Realm`, `-Domain`, `-Kdc`. Opt out of steps with `-SkipWsl` /
`-SkipVSCode` / `-SkipMcp`. Safe to run non-interactively (Intune, SCCM,
PSRemoting), where the host leaves `$PROFILE` empty and the script reconstructs
the path.

Workstations are never enrolled in the realm; they only request tickets.

The WSL provisioning is not SSH-only: it installs both `krb5-user` (for `kinit`
and `ssh`) and `python3-gssapi`, which is what the MCP bridge imports.
See [MCP bridge](#mcp-bridge) below.

Prerequisite: WSL2 with a distro. If missing, once, elevated:
`wsl --install -d Ubuntu-24.04`

Files: `setup.ps1` (provisioner) and `JsoncEdit.ps1` (comment-safe
settings.json editing, kept separate so it can be unit-tested). Download both
from the base URL, or download `setup.ps1` alone and pass `-BaseUrl` so it can fetch the
helper over TLS. The helper is not verified beyond TLS: a digest injected by
the publisher into a script the publisher serves would only prove that host agreed
with itself.

### Ticket forwardability and `-Forwardable`

`setup.ps1 -Forwardable` controls one line of WSL's `/etc/krb5.conf`. It is
off by default, and off is the safer state:

```powershell
.\setup.ps1 -IpaUser jdoe                 # forwardable = false  (default)
.\setup.ps1 -IpaUser jdoe -Forwardable    # forwardable = true
```

Off writes `forwardable = false`, paired with `GSSAPIDelegateCredentials no` for
SSH. A non-forwardable ticket cannot be delegated even by a client that asks to,
so a default fleet is structurally unable to hand its users' credentials to
anything. Leave it off unless you need the next paragraph.

On is required for [D1] on-behalf-of forwarding and pointless otherwise.
Evidence-based S4U2Proxy hard-requires a forwardable caller ticket; without it
the KDC refuses the whole flow with an opaque `KDC_ERR_BADOPTION` that looks
identical to a missing delegation rule.

The trade, stated plainly: forwardable is also what would let a modified client
hand the MCP server a full TGT instead of a narrow evidence credential. The server
refuses that (`delegation.is_narrow_evidence`), so the realm's target allowlist
still applies to everything actually used. The shipped bridge never delegates in
either direction, [CL1]. Turning this on is a deployment decision with a documented
cost, covered in SECURITY.md [D1].

One implementation note for anyone editing that line. It renders from a
pre-computed `$fwd` variable. An inline `$( )` must not go back into that
here-string: bash executes it as root inside WSL, the same render-time-execution
hazard the CA block warns about. An earlier version also tested a `$Forwardable`
that was not a parameter, so it evaluated `$null` and emitted `false`
unconditionally, making a security-relevant value look configurable when it was
not.

The posture question behind the switch is real and unchanged, so decide it
knowingly:

- Forwarding off (what ships). Non-forwardable workstation tickets mean a
  workstation cannot hand a TGT to anything, so the fleet is *structurally* unable
  to delegate. Nothing depends on a server-side check being correct. This is the
  stronger posture and it is the default for that reason.
- Forwarding on. `forwardable = true` is required for [D1] on-behalf-of forwarding
  and is otherwise unnecessary: nothing else in this kit needs it, and SSH
  explicitly does not (see the sentinel block below, which sets
  `GSSAPIDelegateCredentials no` regardless). Turning it on is the deployment
  decision described in [D1] of [SECURITY.md](../SECURITY.md), and it should be
  made there and then reflected here.

Note that `forwardable = false` in `krb5.conf` is strictly stronger than
`GSSAPIDelegateCredentials no` in the ssh config, and that it forecloses
evidence-based S4U2Proxy along with everything else. That is the trade.

### Employees: day to day

```
wsl kinit jdoe@EXAMPLE.INTERNAL     # ~once a week
wslssh anything.example.internal    # no password
wslgit clone https://git.example.internal/org/repo.git
```

`wsl kinit -R` renews without a password (tickets are 24h, renewable 7d). It
renews a *live* ticket and cannot revive an expired one, so once it has lapsed
you need a fresh `kinit`.

Renamed from `kssh`. On a workstation provisioned before the rename, re-running
`setup.ps1` removes the old `kssh` function and adds `wslssh`. Until it is re-run,
that machine still has `kssh` and not `wslssh`, so tell people the new name and the
re-run together rather than one without the other.

Those two cover SSH and VS Code Remote-SSH. If this workstation was also set up
with `-McpUrl`, the same ticket serves MCP, so there is still nothing extra to
type day to day, but see [MCP bridge](#mcp-bridge) for what breaks when the
ticket expires.

### Realm CA

SSH needs no CA (it authenticates with GSSAPI and host keys), so this was easy to
miss: the gap only appears the first time something speaks HTTPS to an internal
host, and it surfaces as `self-signed certificate in chain`, which reads like a
server misconfiguration rather than a missing client trust anchor.

The script therefore fetches the realm CA into WSL's trust store
(`/usr/local/share/ca-certificates/realm-ca.crt`). That fetch is a CA distribution
endpoint and cannot be a trusted channel: WSL has no realm anchor yet, so there is
by construction nothing for TLS to validate the CA against. This is why the
transport cannot be the control and `-CaSha256` is the pin, delivered out of band.
A copy of `setup.ps1` downloaded from the publisher already carries the pin.
Running the script straight out of the repo checkout does not, so pass it.

This hash is now the only out-of-band trust root in the whole Windows path, so
treat it as one: deliver it the way you would have delivered a signing key (MDM,
Intune parameter, kickstart, a printed handout), and read the value once from an
enrolled host:

```
sha256sum /etc/ipa/ca.crt
.\setup.ps1 -IpaUser jdoe -CaSha256 <hash>
```

Three outcomes, all deliberate:

| Result | Meaning | Effect |
|---|---|---|
| `CA-PIN-MISMATCH` | fetched CA is not the one you pinned | fatal, installs nothing |
| `CA-UNPINNED` | no pin in this copy and none passed | warns, installs nothing, run continues |
| `CA-SKIP` | CA endpoint unreachable | warns, run continues |

`CA-UNPINNED` installs nothing: fetching a CA over an unauthenticated channel and
trusting it because it arrived first is not a control. The run still succeeds,
because SSH authenticates with GSSAPI and host keys and must keep working on a
workstation that cannot reach the CA. The MCP step is the exception: it speaks
HTTPS, so with `-McpUrl` a missing CA is fatal and the script exits non-zero
rather than failing later with an opaque certificate error. Steps 1 to 5 have
already run at that point, so SSH is provisioned either way.

### MCP bridge

Opt-in and off by default. An SSH-only workstation is unaffected; nothing in this
section runs unless you pass `-McpUrl`.

```powershell
.\setup.ps1 -IpaUser jdoe `
    -BaseUrl https://mcp.example.internal/client `
    -McpUrl  https://mcp.example.internal `
    -CaSha256 <hash>
```

`-BaseUrl` is mandatory with `-McpUrl` and the run throws without it. `-BaseUrl`
is the publisher directory the bytes come from,
`https://mcp.example.internal/client` by default; `-McpUrl` is the API the bridge
will talk to, and nothing is ever downloaded from it. By default the same host
also serves the kit at `/client`, a different URL on the same machine from the API
endpoint.

The realm CA must already be in WSL's trust store by this point, because the
bridge install speaks HTTPS to the publisher. With `-McpUrl` a missing CA is
fatal, so pass `-CaSha256` unless you are running a copy of `setup.ps1`
downloaded from the publisher.
See [Realm CA](#realm-ca) above.

That does two things:

1. Inside WSL, installs the bridge to `/opt/mcp-krb/mcp-krb-bridge.py` by
   downloading `install-bridge.sh` from the publisher over HTTPS and running it. The
   TLS leg is validated against the realm CA installed in step 2, so the CA pin
   is what stands behind this, and nothing else does: a compromised publisher
   serves whatever it likes to a root shell inside WSL (SECURITY.md [SC1]).
   It is never installed from the repo checkout: `/mnt/c` reports every file as
   `0777`, and it would be a second trust path with no pin on it at all.
2. On Windows, registers the server with Claude Code at user scope, so the tools
   are available from every folder rather than one project. It prefers
   `claude mcp add-json --scope user internal-tools ...` when the `claude` CLI is
   on PATH. A workstation with only the Claude Code desktop app has no such CLI,
   which is now the common case, so the installer falls back to writing the same
   entry into `%USERPROFILE%\.claude.json` itself. Without that fallback the
   bridge would be installed and correctly configured but unreachable, and the
   operator told to run a command they have no binary for.

   That file also holds unrelated session state, so the fallback is deliberately
   conservative: it round-trips the whole document rather than editing it as
   text, refuses to touch a file that does not parse, never overwrites an
   existing `internal-tools` entry (it may have been tuned by hand), re-parses
   the result before it replaces anything, and copies the original to
   `.claude.json.bak` first. Restart the app, or open a new session, to pick it
   up.

#### Why the registration goes through `wsl.exe`

Claude Code runs on Windows. The Kerberos ticket lives in WSL. So the
bridge cannot be launched as `/usr/bin/python3`, which is the form both Linux
examples in `bridge/examples/` use and which Windows simply cannot execute. It is
launched through `wsl.exe` instead. The generic shape is committed as
[`bridge/examples/mcp.json.windows.example`](bridge/examples/mcp.json.windows.example):

```json
{
  "mcpServers": {
    "internal-tools": {
      "type": "stdio",
      "command": "wsl.exe",
      "args": ["-e", "/usr/bin/python3", "/opt/mcp-krb/mcp-krb-bridge.py", "https://mcp.example.internal/"]
    }
  }
}
```

Add `-d <distro>` on any machine with Docker Desktop. A bare `wsl.exe -e`
targets the default distro, and Docker Desktop registers `docker-desktop`,
which frequently ends up as the default and has none of this provisioning. The
symptom is the bridge failing instantly with no ticket and no `python3-gssapi`.
The committed example stays generic because JSON takes no comments, but the
registration the script generates always names the distro it provisioned:

```json
"args": ["-d", "Ubuntu-24.04", "-e", "/usr/bin/python3", "/opt/mcp-krb/mcp-krb-bridge.py", "https://mcp.example.internal/"]
```

Check yours with `wsl --list --verbose`; the `*` marks the default.

#### Verify

```powershell
claude mcp list              # internal-tools should appear
```

For a real round trip, ask Claude Code to list the tools from `internal-tools`,
or run one tool call. A successful `tools/list` proves ticket, TLS trust and
server-side authorization all work.

#### When it stops working

An expired ticket breaks MCP calls exactly as it breaks Remote-SSH, and just as
silently: the tool call fails, not the login. Same fix.

```powershell
wsl kinit -R                 # or a full: wsl kinit jdoe@EXAMPLE.INTERNAL
```

`-McpUrl` must be `https://`; the script rejects anything else, because the
bridge sends a Kerberos `Negotiate` token on every request.

### Why `wslssh` and not `ssh`

Deliberate. An earlier version aliased `ssh` itself, and that was a mistake:
ssh inside WSL reads *WSL's* `~/.ssh`, so hijacking the name silently breaks

- every private key (they live in the Windows `~/.ssh`; WSL's is empty, and
  `-i /mnt/c/...` fails too because drvfs reports files as `0777` and OpenSSH
  refuses world-readable private keys),
- every named `Host` alias in the Windows config: those stop *resolving*, not
  just authenticating, so the error is a DNS failure with no hint of the cause,
- `known_hosts`, and the Windows ssh-agent (unreachable from WSL).

It is also both too broad and too narrow: PowerShell aliases are not inherited by
child processes, so it captures interactive PowerShell while missing cmd.exe,
scripts and CI. The same command name then means two different programs
depending on where you type it. And `scp`/`sftp`/`rsync` are not aliased, so file
transfer to the very hosts this kit serves would silently fall back to the
Kerberos-incapable Windows binary.

`wslssh` is a PowerShell function rather than a `.bat`, because batch `%*` is
re-parsed by cmd.exe, so an argument containing `& | < > ^` becomes local command
execution. `@args` splats safely with no cmd layer. The `.bat` exists only
because VS Code's `remote.SSH.path` needs a file on disk, and is not for
interactive use.

### Why `wslgit` and not `git`

Same reasoning as `wslssh`, and the case against hijacking the name is stronger
here. Editors, build tools and coding agents all shell out to plain `git`;
redirecting the name would break every one of them, and would make each local
operation pay a WSL round trip for nothing.

Only the verbs that talk to a server need a ticket:

| needs `wslgit` | plain `git` is fine |
|---|---|
| `clone` `fetch` `pull` `push` | `status` `add` `commit` `diff` `log` |
| `ls-remote` `remote show` | `branch` `switch` `merge` `rebase` `stash` |
| `submodule update --init` | everything else local |

The function proxies all of git regardless, so nobody has to memorise that
table. The rule to teach is "if it talks to the server, `wslgit`", and using it
for local work merely costs a round trip instead of failing.

It carries `--cd "$PWD"` where `wslssh` does not, because git is
directory-sensitive. `wsl.exe` translates the Windows working directory, which
is what allows the checkout to live on the Windows filesystem while the network
call happens where the ticket is. That combination is the point: the working
tree stays somewhere Windows tools can reach at full speed, and WSL is only a
transport.

One caveat for large repositories: `/mnt/c` goes through the 9p bridge and is
slow. Fine for ordinary source trees, noticeably slow for one with tens of
thousands of files. If a clone ever feels wrong that is why, and the fix is to
keep that single repository inside WSL rather than to change the pattern.

### Line endings, when two gits share one worktree

Windows git defaults to `core.autocrlf=true`; git in WSL assumes `false`. With
the checkout on the Windows filesystem, both operate on the same files and each
sees the other's work as modifications. After a plain `git checkout -- .` on the
Windows side:

```
windows git status : clean
wsl     git status :  M README.md;  M notes/a.md;  M notes/b.md
```

Three files phantom-dirty depending only on which git you asked.

`setup.ps1` pins the Windows side to `false` so the two agree, and skips that if
`core.autocrlf` was set to something deliberate. The durable fix belongs in the
repository rather than the workstation:

```
* text=auto eol=lf
```

in `.gitattributes`. That travels with the repo, so it holds however each clone
was provisioned.

### When git says `Authentication failed`

```
$ git clone https://git.example.internal/org/repo.git
fatal: Authentication failed for 'https://git.example.internal/org/repo.git/'
```

This is the most common report from a Windows workstation, and the wording sends
people looking for a password that does not exist. Nothing is misconfigured: the
command was simply run by Windows git instead of `wslgit`.

It is confusing because git *looks* equipped for the job. The bundled curl
advertises the right features:

```
$ curl --version | tr ' ' '\n' | grep -iE 'SPNEGO|GSS|SSPI'
Kerberos
SPNEGO
SSPI
```

SPNEGO is compiled in. What is missing is the credential. SSPI reads the Windows
LSA ticket cache, and on a machine that is not joined to the realm that cache is
empty:

```
$ klist
Current LogonId is 0:0x4607b
Cached Tickets: (0)
```

`kinit` in WSL fills WSL's own cache, which SSPI cannot see. So the capability is
present, the ticket is elsewhere, and the request goes out unauthenticated and
comes back 401.

Confirm the diagnosis in one line, from the same directory:

```
wslgit ls-remote
```

If that succeeds, nothing is wrong with the repository, the network or the
credential. Use `wslgit` for clone, fetch, pull and push.

If it fails too, the ticket itself has expired. `kinit -R` renews a live ticket
and cannot revive a dead one, so run `wsl kinit <user>@<REALM>` and try again.

### Why WSL and not Windows' own ssh

`C:\Windows\System32\OpenSSH\ssh.exe` accepts `GSSAPIAuthentication yes` and will
even attempt `gssapi-with-mic`, but its GSSAPI is a shim over the Windows LSA
store (`GSSAPI_SSPI 1`, `KRB5` compiled out). It cannot read the cache `kinit`
writes, so it fails with `GSS_S_FAILURE`. No configuration changes this; the
upstream request for a user-supplied GSSAPI library was closed unimplemented.

Git Bash's ssh *is* GSSAPI-capable (Heimdal) but ships no `kinit` and could not
consume an MIT-written cache (`Miscellaneous failure`). Cygwin works but ships an
orphaned krb5 from 2018. WSL2 wins because `kinit` and `ssh` there are the same
MIT krb5 stack reading one cache, and it is patchable via `apt`.

### Ticket cache location

`/home/<user>/.krb5/ccache`, set via `default_ccache_name` in `krb5.conf` so
`kinit` and ssh agree without environment variables. Deliberately not:

- `/tmp`: systemd-tmpfiles wipes it on boot, and WSL2 shuts its VM down after
  ~60s idle, so tickets would vanish several times a day.
- `/var/tmp`: persistent, but `1777` with a predictable filename, so another uid
  can squat it. (Confidentiality is not the issue: MIT creates the cache `0600`
  and uses `unlink()` + `O_CREAT|O_EXCL`. Denial of service is.)

### ssh config

One wildcard, in a sentinel-delimited managed block in WSL's `~/.ssh/config`:

```
# BEGIN setup-workstation
Host *.example.internal
    User jdoe
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no
# END setup-workstation
```

No per-host entries, ever. Re-running with a different `-IpaUser` rewrites the
block. `GSSAPIDelegateCredentials no` plus `forwardable = false` in `krb5.conf`
enforce the no-delegation posture ([CL1] in ../SECURITY.md); note that the second is
strictly stronger, and forecloses evidence-based S4U2Proxy. See
[Ticket forwardability and `-Forwardable`](#ticket-forwardability-and--forwardable)
for what that costs you if you want [D1].

### VS Code Remote-SSH

The script sets these for you (backing up `settings.json`, preserving comments):

```json
"remote.SSH.path": "C:\\Users\\<you>\\bin\\ssh-dispatch.bat",
"remote.SSH.useLocalServer": false,
"remote.SSH.enableDynamicForwarding": false
```

`remote.SSH.enableDynamicForwarding` is off on purpose. Its default routes VS
Code's link to the remote server through a SOCKS proxy that the WSL ssh opens
inside WSL's own network namespace. On a cold connect, Windows can try to reach
that port before WSL has mirrored it to the Windows loopback, which surfaces as
`connect ECONNREFUSED 127.0.0.1:<port>` after the remote server has already
started, and often as a follow-on "extension failed to launch" error that is
really just the dead connection rather than anything wrong with the extension or
its binary. A plain TCP forward sidesteps that timing. The port still lives in
WSL, so if the failure ever recurs the durable fix is WSL mirrored networking:
put `networkingMode=mirrored` under `[wsl2]` in `%USERPROFILE%\.wslconfig`, run
`wsl --shutdown`, and reconnect, which shares one namespace between WSL and
Windows so the mirror step disappears. That is a machine-wide network change and
can affect some VPNs, so it is left to the operator rather than written by the
installer.

`remote.SSH.path` is global (VS Code uses it for every Remote-SSH host), so
`ssh-dispatch.bat` routes by destination rather than forcing a choice:

| Destination | Goes to | Why |
|---|---|---|
| `*.example.internal` | WSL ssh | Kerberos/GSSAPI |
| anything else | `System32\OpenSSH\ssh.exe` | your existing keys, `Host` aliases, `known_hosts` |

So one VS Code profile serves both worlds. You do not need *Profiles: Create
Profile*, and existing Remote-SSH hosts keep working untouched.

Then *Remote-SSH: Connect to Host* and type the FQDN. VS Code builds its dropdown
from the Windows ssh config while realm connections run ssh inside WSL.
A wildcard yields no dropdown entries, so type the hostname.

#### Dispatcher limits (measured, not theoretical)

`ssh-dispatch.bat` is for VS Code only. Humans use `ssh` (other hosts) or
`wslssh` (realm hosts); both are cmd-free and immune to everything below.

Verified working: real GSSAPI connections, exit-code propagation (returns 42
for `exit 42`, which Remote-SSH depends on), and quoted multi-word arguments
preserved byte-for-byte.

Verified failure modes, all outside how VS Code invokes it:

| Failure | Example | Why |
|---|---|---|
| cmd metacharacters run locally | `wslssh h "echo A&echo B"` via the .bat → `echo B` executes on Windows | cmd re-parses the line before the script runs. Inherent to any `.bat`; only a compiled `.exe` shim would fix it |
| substring false positive | `ssh-dispatch.bat legacy-host "cat /etc/hosts.example.internal"` → routed to WSL | routing greps the whole argument string for the domain |
| named alias for a realm host | `Host myvm` → `HostName host1.example.internal` | the literal argument has no domain, so it goes to Windows ssh and fails. Use FQDNs for realm hosts |

Sharing one host list between the two is not possible: `Include
/mnt/c/.../.ssh/config` from WSL fails with `Bad owner or permissions`, because
drvfs reports files as `0777` and OpenSSH enforces strict permissions on included
files (it does not for `-F`).

Tickets expire and VS Code reconnects silently, so an expired ticket looks like
the extension breaking. Run `wsl kinit -R`.

### Reaching a Kerberos-only web page from Windows

A Windows browser cannot do this, and the failure is misleading enough to be
worth stating plainly: you get an authentication dialog, you type the correct
password, and the dialog comes straight back. Forever.

Nothing is wrong with the password. SPNEGO never uses one. The browser is meant
to answer the `WWW-Authenticate: Negotiate` challenge with a ticket from the
operating system's credential cache, and a workstation that is not joined to
the realm has no such ticket. Windows' own cache is empty, your tickets live
inside WSL, and a Windows process cannot see them. With nothing to answer with,
the browser falls back to prompting; what you type goes up as Basic or NTLM,
both of which the server refuses because it pins krb5; and you get a fresh 401.

So the browser has to run where the ticket is, and **`setup.ps1` does this for
you**. There is nothing to run by hand: it installs Firefox inside WSL and
configures it, as part of the same single command that sets up SSH and the
bridge. `-SkipFirefox` opts out on a machine that has no business browsing.

What it does, and why each part is there:

Ubuntu's `firefox` package is a transitional shim for the snap, which is
unreliable under WSL, so the real `.deb` comes from Mozilla's own APT
repository. Adding a repository means adding a party that can put root-run code
on the machine, so the signing key's fingerprint is checked
(`35BAA0B3…15A3`) **before** the repository is added, and a mismatch deletes the
key and installs nothing.

Configuration goes in `/etc/firefox/policies/policies.json` rather than
per-profile preferences, so it survives a new profile and there is one place to
read when someone asks what this browser is configured to trust:

```json
{
  "policies": {
    "Preferences": {
      "network.negotiate-auth.trusted-uris": {
        "Value": ".example.internal", "Status": "locked"
      }
    },
    "Certificates": { "Install": ["/usr/local/share/ca-certificates/realm-ca.crt"] }
  }
}
```

The certificate line is not optional on Linux: Firefox keeps its own NSS trust
store and does not read the system one by default, so without it every realm
host fails TLS.

**`network.negotiate-auth.delegation-uris` is deliberately never set.** That pref
forwards your TGT to the listed hosts, which is precisely what the rest of this
design refuses to do. A test asserts it stays absent.

Everything above is recorded in the install manifest, so `uninstall.sh` removes
the package, the repository, its pin and keyring, and the policy file. A machine
that already had the Mozilla repository keeps it.

On Windows 11 the window appears on your desktop through WSLg, with a Start menu
entry generated from the `.desktop` file. Pin your own shortcut to
`wslg.exe -d <distro> -- firefox` rather than the generated one: WSL puts that
shortcut's icon under `%LOCALAPPDATA%\Temp`, and once Temp is cleared a pinned
copy reports the program as moved or missing.

None of this is needed for pages that offer their own login form; it applies
only where Kerberos is the sole accepted mechanism. The policy editor is one
such page, and it also exposes `/admin/authz.json`, so
`curl --negotiate -u : https://mcp.example.internal/admin/authz.json` reads and
writes the same policy from a shell with no browser at all.

## macOS

`setup-macos.sh` is the macOS counterpart to `setup.sh` and `setup.ps1`, with one
structural difference: a Mac never joins the realm. There is no
`ipa-client-install` for it, so the script configures the Kerberos client, SSH, the MCP
bridge, and the realm CA if that is switched on, then stops there. The realm never learns the
machine exists, which is why macOS genuinely leaves FreeIPA untouched where Linux
does not.

It is idempotent, writes an install manifest so `uninstall.sh` can reverse it, and
takes `--dry-run` to print the plan without changing anything. The provisioning page
the MCP host serves at `/client/` carries both the one-line invocation and the same
steps by hand, for anyone who would rather not run a downloaded script. The rest of
this section is the shape and the one trap.

The trap, because it costs an afternoon otherwise: the `krb5.conf` KDC line must be

```
kdc = tcp/ipa.example.internal
```

with the `tcp/` prefix. macOS ships Heimdal rather than MIT krb5, and Heimdal has no
`udp_preference_limit`. Over UDP the KDC issues the ticket and the oversized reply
is dropped by any VPN with a small MTU, so the client reports *"unable to reach any
KDC in realm"* about a KDC that already answered. The error points nowhere near the
cause.

The rest is standard: `/etc/resolver/<domain>` for split DNS to the realm resolver,
a `krb5.conf` with `[realms]`/`[domain_realm]`, `~/.ssh/config` with
`GSSAPIAuthentication yes` and `GSSAPIDelegateCredentials no` ([CL1]), then `kinit`.
Use `klist -v` to see flags, not `klist -f` (the MIT spelling). SSH via GSSAPI works.

The realm CA is required, and `setup-macos.sh` refuses to run without
`--ca-sha256`. `kinit` and `ssh` do not need it, since GSSAPI and host keys cover
those, but the bridge speaks HTTPS to the MCP host and without the CA that fails
with a certificate error that reads like a bug in the bridge. The fetch is plain HTTP, so the hash
comparison is the entire check, and the expected value has to reach you from
somewhere other than the infrastructure serving the file:

```sh
curl -fsS -o /tmp/realm-ca.crt http://ipa.example.internal/ipa/config/ca.crt
shasum -a 256 /tmp/realm-ca.crt        # must equal the value you were given
sudo security add-trusted-cert -d -r trustRoot \
     -k /Library/Keychains/System.keychain /tmp/realm-ca.crt
```

VS Code needs no configuration on macOS. The three `remote.SSH.*` keys `setup.ps1`
writes on Windows exist only to push `ssh` across the WSL boundary; a Mac's
`/usr/bin/ssh` already speaks GSSAPI and already reads the `~/.ssh/config` above. If
`ssh host` works in Terminal, Remote-SSH works.

One thing not to tidy up: the macOS `krb5.conf` deliberately leaves
`default_ccache_name` unset, unlike the WSL one this kit writes, which pins a
`FILE:` cache. macOS defaults to a session-wide cache, `KCM:` up to Ventura and
`API:` from Sonoma, and that is what lets an application launched from the Dock,
inheriting no shell environment, still find the ticket. Pinning a `FILE:` path to
match the WSL config would break GUI launches in a way that looks unrelated to the
change that caused it.

The MCP bridge runs on macOS too. The packaging problem that once blocked it no
longer exists: python-gssapi has shipped macOS wheels for x86_64 and arm64 since
1.7.2, so `pip install gssapi` needs no compiler and no Xcode CLT, and the bridge
itself calls nothing platform-specific. The provisioning page carries the steps
(a per-user venv under `~/Library/Application Support/mcp-krb/`, then the same
`claude mcp add` registration the Linux installer prints).

Why it works, recorded so nobody re-litigates it in a year: the worry worth
checking was which Kerberos the wheel resolves. A bundled MIT krb5 would look for
the ticket in `FILE:/tmp/krb5cc_<uid>` and report no credentials cache while
`klist` showed a perfectly valid one sitting in the system's `KCM:` (Ventura and
earlier) or `API:` (Sonoma and later) cache. It does not: both published wheels
ship no `.dylibs/` directory, and every extension module carries exactly one
`LC_LOAD_DYLIB`, `/System/Library/Frameworks/GSS.framework/Versions/A/GSS`. That
is the system Heimdal, the same library behind `kinit` and `klist`, so the bridge
and the user's ticket share one credential cache and the Sonoma ccache-default
change is invisible to it.

What that linkage evidence is not: a smoke test. This path has not been exercised
end to end against the MCP server from a Mac; the one untested step is a Heimdal
SPNEGO initiator against the server's MIT acceptor, the same pairing every Mac
that SSHes into a FreeIPA realm already exercises daily. Expected to work, not
yet earned the word "supported".

### Browsers on macOS

This is the one place macOS is easier than Windows. It has a real Kerberos, the
system Heimdal behind `kinit` and `klist`, so a native browser can answer a
`Negotiate` challenge with the ticket you already hold. There is no equivalent of
the Windows problem, where the LSA cache is empty on an unjoined machine and the
browser has nowhere to read a ticket from. Nothing needs to run inside a VM.

Get a ticket first, then point the browser at the internal URL:

```
kinit jdoe@EXAMPLE.INTERNAL
```

| browser | what it needs |
|---|---|
| Safari | nothing; it uses the system ticket as it stands |
| Chrome | `defaults write com.google.Chrome AuthServerAllowlist "*.example.internal"` |
| Edge | `defaults write com.microsoft.Edge AuthServerAllowlist "*.example.internal"` |
| Firefox | `network.negotiate-auth.trusted-uris` = `.example.internal`, in `about:config` |

Chrome and Edge are the same engine and the same key under different bundle
identifiers. Neither has an intranet zone to infer trust from the way Windows
does, so the allowlist is not optional on either: without it they send nothing
and the page just keeps asking. Quit and reopen the browser after setting it.

Deliberately absent from all four: any delegation setting. Firefox's
`network.negotiate-auth.delegation-uris` and the Chromium
`AuthNegotiateDelegateAllowlist` forward the TGT to the site, which is the one
thing this design refuses. Trusting a host to receive a service ticket is not the
same as handing it your identity, and only the first is wanted here.

If a page prompts for a password anyway, it is one of two things and neither is
the server. `klist` with no ticket means run `kinit`. A TLS error before any
prompt means the realm CA is not trusted, which `setup-macos.sh` handles with
`security add-trusted-cert`.

## The bridge itself

Everything above installs three files from `bridge/`. This section is what the
first of them is; the other two are covered under
[Fetching a file](#fetching-a-file-mcp-fetch).

Claude Code talks to a tiny local process over stdio; the bridge forwards each
JSON-RPC message to the Kerberized MCP server with a fresh
`Authorization: Negotiate` token minted per request from the developer's FreeIPA
login ticket. No passwords, no API keys, no per-dev secrets.

```
Claude Code ──stdio──▶ mcp-krb-bridge.py ──HTTPS + Negotiate──▶ nginx ──▶ Python MCP server
                        fresh token per request                          (../server/)
```

A fresh token per request keeps the server's Kerberos replay cache on: no RFC
4120 violation, and no token that can age into a 401. Cost: one lightweight local
Python process per session. Analysis in [../SECURITY.md](../SECURITY.md);
concepts in [the root README](../README.md).

### Transport, precisely

The usual case is HTTPS, but the exact rule the code enforces is narrower than
"HTTPS only" and it is worth knowing which:

- a scheme that is not `http` or `https` is refused outright;
- `http://` is refused to any non-local host. It is permitted only to
  `localhost`, `127.0.0.1` and `::1`, which is what makes a loopback test rig
  possible without weakening the fleet rule;
- `MCP_KRB_NOAUTH=1` drops the `Authorization` header entirely. Local testing
  only. It is not a fallback and not a degraded mode; it produces a bridge that
  authenticates nobody.

Note the split of responsibility: `setup.ps1` rejects any `-McpUrl` that is not
`https://` at provisioning time, which is stricter than what the bridge itself
enforces at runtime. That is intentional. A provisioned workstation has no reason
to talk to loopback.

### Sessions

The bridge tracks `Mcp-Session-Id` and, if the server 404s a session, transparently
re-initializes and retries. Against this server that machinery never engages:
`server/mcp_server.py` runs with `stateless_http=True`, so no session id is ever
issued or honoured server-side. The bridge forwards a session id opaquely if
it ever sees one and never treats it as a credential. Authorization is the
per-request Negotiate token and only that. The bridge keeps the code path because
it is a general Streamable-HTTP client, not because this deployment needs it.

Two more behaviours: SSE-encoded POST responses are parsed and each event is
forwarded, so progress notifications during long tool calls work; and the
standalone GET stream for unsolicited server-to-client push is not opened,
because plain tool servers do not need it.

### No credential delegation, from the client side

The bridge builds its GSSAPI context explicitly without `delegate_to_peer`,
so it never forwards the user's TGT to the server. That equals python-gssapi's
safe default and is stated explicitly for auditability. A test asserts the flag is
absent.

This stopped being belt-and-braces the day [D1] shipped. Enabling
on-behalf-of forwarding requires workstation tickets to be forwardable, and a
forwardable ticket is exactly what a client needs in order to hand over a TGT
instead of the narrow S4U2Proxy evidence credential. The KDC's own target
allowlist does not constrain a forwarded TGT. The server refuses that credential
outright (`delegation.is_narrow_evidence`), so the allowlist does apply to
everything actually used, and a client that tried it would simply be denied.
Proven on a live KDC. So the flag list here is the reason *our* clients stay on
the safe side of that line, and adding `delegate_to_peer` would quietly convert
every user of this bridge into the hostile-client case. See [CL1] and
[D1] in [SECURITY.md](../SECURITY.md).

### Registering it with Claude Code

Three ways, in descending order of blast radius:

1. Fleet-wide, `/etc/claude-code/managed-mcp.json`. What `install-bridge.sh --managed`
   writes. Shape committed as
   [`bridge/examples/managed-mcp.json.example`](bridge/examples/managed-mcp.json.example).
2. Per user, via `claude mcp add-json --scope user internal-tools ...`. What
   `setup.ps1` runs on Windows. Without `--managed`, `install-bridge.sh` prints the
   equivalent command and changes no configuration.
3. Per repo, by committing
   [`bridge/examples/mcp.json.example`](bridge/examples/mcp.json.example) as
   `.mcp.json`.

The two Linux examples launch `/usr/bin/python3` directly. The Windows one
launches through `wsl.exe`; see
[Why the registration goes through `wsl.exe`](#why-the-registration-goes-through-wslexe)
for why, and for the `-d <distro>` warning that matters on any machine with
Docker Desktop.

### Notes

- TLS trust: the bridge uses the system store (the IPA CA is already trusted
  on an enrolled host, and `setup.ps1` puts it in WSL's store). `--ca <pem>` for
  edge cases.
- `python3-gssapi` is not automatic everywhere. On an IPA-enrolled Linux
  workstation it arrives with `ipa-client`, so there is nothing to install.
  Inside WSL this is false: the WSL distro is *not* IPA-enrolled and has no
  `ipa-client`, so `python3-gssapi` (and `krb5-user` for `kinit`) must be
  installed explicitly with `apt`. `setup.ps1` does this for you. If you are
  setting WSL up by hand, do it first or the bridge dies on `import gssapi`.
- Windows devs run the bridge inside WSL2. On a non-domain-joined Windows
  box, SSPI has no MIT ccache and falls back to NTLM, which the server rejects.
  `pip install pyspnego` does not change that.
- Verified: the hermetic unit suite (`sh ../tests/run-tests.sh`, which prints
  the count, which is why none is written here) plus a live end-to-end run on real
  FreeIPA (bridge and server, including replay rejection).

## Fetching a file: `mcp-fetch`

Some content has to arrive byte-exact. A schema, a lockfile, a fixture, a
config: a paraphrase of it is not it. Passing that through a model as text is
the wrong shape, so the installers put a small command on `PATH`:

```
mcp-fetch https://host.example.internal/schema.json -o schema.json
mcp-fetch https://host.example.internal/schema.json -o schema.json --sha256 <hex>
```

It authenticates with SPNEGO, streams to a temporary file in the destination
directory, and renames only once the body is complete and any digest you gave
matches. A failure therefore leaves no file at all, rather than a short one.
Exit codes: `0` ok, `2` no Kerberos, `3` HTTP, `4` hash mismatch, `5` refused.

It is deliberately **not** an MCP tool. The caller already holds the ticket
that would authorise it, so putting a GET behind a server call would add a hop,
a schema and an audit line while changing nothing about what is possible.

What it refuses, and why, since these are the cases where a URL or a path came
from model output rather than from you:

| refused | because |
|---|---|
| `http://` | a `Negotiate` header in cleartext is observable |
| a host outside the realm suffix | widen it deliberately with `--allow-host-suffix` |
| any 3xx | forwarding an `Authorization` header across a cross-origin redirect has a long CVE history; fetch the final URL |
| a destination outside the working directory | `--allow-outside` if meant |
| an existing file, a symlink, a directory | `--force` for the first; never the others |
| a body over `--max-bytes` (8 MB default) | enforced as the bytes arrive |
| a path like `C:\tmp\x` off Windows | inside WSL that creates a file named literally that and exits 0 |

On Windows the command is a PowerShell function, because the ticket lives in
WSL. It translates an absolute `-o C:\...` with `wslpath -u` before handing it
over; relative paths need no help, since `wsl.exe` inherits the working
directory.

### Using it from a shared host

A shared dev host holds a *machine* keytab and no user ticket, by design:
`ssh` runs with `GSSAPIDelegateCredentials no`, so nothing of yours is copied
there. That leaves it unable to fetch anything as you, which is the point.

The answer is to forward the socket rather than the credential. On the
workstation, serve the two things a remote client needs:

```
mcp-krb-bridge.py --listen ~/.mcp-krb.sock https://mcp.example.internal/ &
mcp-krb-bridge.py --fetch-listen ~/.mcp-krb-fetch.sock &
```

Then forward both, which `~/.ssh/config` can do for you:

```
Host dev.example.internal
    RemoteForward /run/user/1000/mcp-krb.sock       /home/you/.mcp-krb.sock
    RemoteForward /run/user/1000/mcp-krb-fetch.sock /home/you/.mcp-krb-fetch.sock
```

`RemoteForward` has taken Unix socket paths since OpenSSH 6.7. Use your own uid
on the remote (`id -u`) in the left-hand paths; `~` is not expanded on that
side. On the far end, `mcp-fetch` notices the socket and asks the workstation
instead of trying to do it itself, and an MCP client is pointed at
`mcp-krb-remote-bridge.py /run/user/1000/mcp-krb.sock`, which joins its stdio
to the socket and holds nothing.

**Set `StreamLocalBindUnlink yes` in the remote's `sshd_config`.** The default
is `no`, which leaves the socket file behind when a session ends, and the next
connection then fails to bind it. The symptom is a forward that worked once and
never again until somebody deletes the file by hand.

What this costs, stated plainly because shared hosts are the case it exists
for: the sockets are `0600`, so an unprivileged peer cannot use them, but
**root on that host can, while your session is open**, which on a box where
colleagues hold sudo means those colleagues. The exposure is bounded by your
session rather than by a ticket lifetime, and it ends when you disconnect. The
alternative, running `kinit` there, leaves a cache root can read and replay to
become you everywhere in the realm for its full lifetime, still valid after you
log out. It is structurally `ssh-agent` forwarding with a narrower grant. The
operational rule that follows is to avoid mixing privilege levels and sudo on
one host.

## Rollback

Two scripts, both driven by the install manifest the installers write, and both
defaulting to a dry run: they print the plan and change nothing until asked.
The scripts are the reference for what is removed and restored; every removal
is justified by a manifest entry saying the installer created it, and every
replaced file or settings key goes back to the recorded prior state rather than
being deleted.

Linux, and inside WSL:

```sh
sudo sh uninstall.sh            # print the plan
sudo sh uninstall.sh --yes      # apply it
```

`--keep-packages` leaves apt/dnf packages alone even where the kit installed
them; `--managed` also removes the machine-wide `/etc/claude-code`
registration, which affects every user on the machine and is therefore opt-in.

Windows, which also cleans the WSL side through the distro the installer
recorded in the manifest, never the default distro:

```powershell
.\uninstall.ps1                 # print the plan
.\uninstall.ps1 -Yes            # apply it
```

macOS has no uninstall script, matching its install. The steps, in reverse order
of the manual procedure:

```sh
# 1. the bridge and its registration
claude mcp remove internal-tools          # or drop the entry from ~/.claude.json
rm -rf "$HOME/Library/Application Support/mcp-krb"

# 2. the trusted CA, if it was ever added. The hash algorithm CHANGES here:
#    add-trusted-cert is verified against the SHA-256 above, delete-certificate
#    matches on the SHA-1, and passing the wrong one silently matches nothing
#    and leaves the certificate trusted.
openssl x509 -noout -fingerprint -sha1 -in realm-ca.crt
sudo security delete-certificate -t -Z <SHA1> /Library/Keychains/System.keychain

# 3. Kerberos, DNS and SSH
sudo rm -f /etc/krb5.conf                 # or restore the copy you kept
sudo rm -f /etc/resolver/example.internal
kdestroy
```

Then delete the `Host *.example.internal` block from `~/.ssh/config` by hand.
Searching that delete command turns up alarming results about SIP blocking
keychain changes: those concern `SystemRootCertificates.keychain`, the
Apple-shipped roots. A CA an administrator added to `System.keychain` is not one
of those and removes normally.

What the scripts deliberately do not do, one line each:

- Un-enrol from FreeIPA. A Linux workstation's host entry and host keytab stay
  on the IPA server; `sudo ipa-client-install --uninstall` is the separate,
  deliberate act that changes that. Windows and macOS never enrol, so the realm
  holds nothing of theirs.
- Unregister the WSL distro. That deletes an entire Linux filesystem;
  `wsl --unregister <distro>` is printed, never run.
- Delete `.bak` files. `settings.json.bak` and `.claude.json.bak` may predate
  this kit, so they are reported by path and left alone.

A workstation provisioned before the manifest existed has nothing recorded, so
both scripts refuse to guess: they print what a manifest would have told them
and exit non-zero, leaving the reversal to you.
