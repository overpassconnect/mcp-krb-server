# One-time Kerberos SSH setup for a Windows workstation (WSL2-based).
#
# Windows' built-in ssh.exe cannot do Kerberos: its GSSAPI is a shim over the
# Windows LSA store (`GSSAPI_SSPI 1`, `KRB5` compiled out), which is empty on a
# non-AD machine. So ssh runs inside WSL2, where kinit and ssh are one MIT krb5
# stack - the same arrangement that works on macOS and Linux.
#
# Usage (once per machine). -IpaUser, -Domain, -Realm and -Kdc are all required:
#     .\setup.ps1 -IpaUser jdoe `
#         -Domain example.internal -Realm EXAMPLE.INTERNAL `
#         -Kdc ipa.example.internal
#
# The minimal case, one file, nothing else needed:
#     .\setup.ps1 -IpaUser jdoe `
#         -Domain example.internal -Realm EXAMPLE.INTERNAL `
#         -Kdc ipa.example.internal -SkipVSCode
# That provisions Kerberos SSH only. It downloads nothing, so it needs no
# -BaseUrl, no -CaSha256 and no network access to a publisher. Copy this single
# script to the workstation and run it elevated. Drop -SkipVSCode if you also
# want VS Code Remote-SSH, the only part that needs JsoncEdit.ps1 beside it.
#
# Optionally also provision the MCP bridge (off by default, so an SSH-only
# workstation is unaffected):
#     .\setup.ps1 -IpaUser jdoe `
#         -BaseUrl https://mcp.example.internal/client `
#         -McpUrl  https://mcp.example.internal
#
# Two URLs, two roles; they may be the same host.
#   -BaseUrl is the publisher: the directory serving setup.ps1, JsoncEdit.ps1,
#            install-bridge.sh and the bridge .py, all under plain names.
#   -McpUrl  is the Kerberized MCP API the installed bridge talks to. It is
#            written into the Claude Code registration.
#            The MCP host serves the client bundle at CLIENT_PATH (default
#            /client/) by default, so -McpUrl and -BaseUrl are normally the same
#            host and -BaseUrl is https://<mcp-host>/client. With run.sh
#            --no-serve-client it serves the API alone, and the bundle is served
#            from wherever you copied an exported copy. Either way this script
#            downloads from -BaseUrl, so point it at wherever the bundle is.
#
# What the bridge install trusts: install-bridge.sh is fetched from -BaseUrl
# over TLS and executed as root inside WSL. TLS is the whole of that assurance.
# A compromised publisher, or anyone who can terminate TLS for it, serves
# whatever installer it likes and this script runs it as root. Nothing this
# script downloads proves its own origin, and the code below does not claim
# otherwise. Anything stronger has to be a trust root the publisher does not
# itself hold, so do not add one that lives on the publisher.
#
# What does authenticate that transport is -CaSha256, the only out-of-band root
# left in the Windows path. WSL is not FreeIPA-enrolled, so unlike a realm host
# it has no /etc/ipa/ca.crt to pin against; step 2 installs the realm CA into
# WSL's trust store and pins it by SHA-256 supplied out of band. That is why an
# unpinned CA installs nothing, a mismatched one is fatal, and a missing one is
# fatal as soon as -McpUrl is asked for.
#
# Afterwards:
#     wsl kinit jdoe@EXAMPLE.INTERNAL     (~once a week; -R renews)
#     wslssh anything.example.internal      (no password)
#
# This deliberately provides `wslssh`, not an `ssh` alias: hijacking `ssh`
# would route every SSH the employee makes through WSL, where their existing
# keys, host aliases, known_hosts and ssh-agent do not exist.
param(
    [Parameter(Mandatory = $true)][string]$IpaUser,
    # No defaults for the three realm values, for the same reason -BaseUrl has
    # none: a wrong-but-plausible default is worse than a refusal. They once
    # defaulted to example.internal etc., and a colleague running the documented
    # one-liner provisioned a workstation for a realm that does not exist,
    # finding out only at kinit, far from the cause.
    [string]$Domain = '',
    [string]$Realm = '',
    [string]$Kdc = '',
    # SHA-256 of the realm CA (sha256sum /etc/ipa/ca.crt on any enrolled host).
    # No default and no publish-time substitution: this is the only out-of-band
    # value left in the Windows path, so it has to come from whoever runs the
    # script rather than from whoever served it; a hash injected by the publisher
    # into a script the publisher serves would be checking that host against
    # itself. Empty means the CA is not installed.
    [string]$CaSha256 = '',
    [string]$WslDistro = 'Ubuntu-24.04',
    # Download base: the publisher's directory everything is fetched from. No
    # default: a wrong-but-plausible default is worse than a refusal, and this
    # value decides which host gets to hand a root shell its installer. Required
    # whenever something has to be downloaded (a missing JsoncEdit.ps1, or the
    # MCP bridge).
    [string]$BaseUrl = '',
    # Opt-in: base URL of the Kerberized MCP API the bridge talks to. That host
    # serves the bundle too by default, in which case -BaseUrl points at it too.
    # Empty means "SSH only".
    [string]$McpUrl = '',
    [switch]$SkipWsl,
    [switch]$SkipVSCode,
    # Kerberos ticket forwardability, written into WSL's /etc/krb5.conf.
    # Off by default, the safer state: see the block above the here-string for
    # what turning it on buys and costs. Required for SECURITY.md [D1]
    # on-behalf-of forwarding, pointless otherwise.
    [switch]$Forwardable,
    [switch]$SkipMcp
)
$ErrorActionPreference = 'Stop'

# --- argv validation, all of it, before anything runs ------------------------
# Every parameter below is interpolated into a here-string that is executed by
# bash as root inside WSL (steps 2 and 3), so a malformed value is root command
# execution reachable from argv alone. argv is not always typed by the person
# at the keyboard: an MDM/Intune template, an SCCM task sequence or a wiki
# copy-paste all supply it, and none of those channels is a trust boundary.
#
# Each shape below is the real one for the thing it names:
#   -Kdc / -Domain  DNS names: labels of alphanumerics and inner hyphens,
#                   dot-separated. No underscore (not legal in a hostname), no
#                   trailing dot, no empty label.
#   -Realm          a Kerberos realm, conventionally the uppercase domain. Both
#                   cases are accepted because a realm is case-sensitive and
#                   forcing one here would silently break a lowercase realm,
#                   but the charset is the same DNS-shaped one.
#   -IpaUser        a POSIX login name. FreeIPA also permits a trailing '$' for
#                   machine accounts; it is excluded deliberately because this
#                   is an interactive human's login and '$' is the one character
#                   that could still mean something to a later expansion. A
#                   leading '-' is refused separately: it would be read as a
#                   flag rather than a value.
#   -CaSha256       a SHA-256, so exactly 64 hex characters, or empty (= "do
#                   not install the CA", the documented default).
#
# Refuse loudly and early. A wrong value here cannot be recovered from further
# down, and a half-provisioned workstation is worse than one that never started.
$dnsName = '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$'
# One https-URL shape, used for both -McpUrl and -BaseUrl. Hoisted like $dnsName
# so the two URL rules cannot drift apart. The charset is deliberately narrow:
# both values are interpolated into single-quoted shell words in the step-6
# here-string, so a quote or semicolon in the path would break out and run as
# root inside WSL. Validate the shape once, here, instead of quoting later.
$httpsUrl = '^https://[A-Za-z0-9._-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$'

# Presence first, shape second. Checked here rather than with Mandatory=$true on
# the parameters, because Mandatory prompts when a value is missing, and this
# script is run unattended by MDM, Intune and SCCM task sequences as often as by
# a human. A prompt in that context hangs the job instead of failing it.
$missing = @()
if (-not $Domain) { $missing += '-Domain (e.g. example.internal)' }
if (-not $Realm)  { $missing += '-Realm (e.g. EXAMPLE.INTERNAL, usually the domain uppercased)' }
if (-not $Kdc)    { $missing += '-Kdc (e.g. ipa.example.internal, your FreeIPA server)' }
if ($missing.Count -gt 0) {
    throw ("Missing required realm settings: " + ($missing -join '; ') + ". These have no defaults on purpose: a wrong one provisions a workstation for a realm that does not exist and fails later at kinit, far from the cause. Ask whoever runs your FreeIPA for the three values.")
}

if ($Kdc -notmatch $dnsName) {
    throw "-Kdc must be a DNS hostname (letters, digits, hyphens, dots) and nothing else (got '$Kdc')."
}
if ($Domain -notmatch $dnsName) {
    throw "-Domain must be a DNS domain (letters, digits, hyphens, dots) and nothing else (got '$Domain')."
}
if ($Realm -notmatch $dnsName) {
    throw "-Realm must be a Kerberos realm in DNS form, e.g. EXAMPLE.INTERNAL (got '$Realm')."
}
if ($IpaUser -notmatch '^[A-Za-z0-9_][A-Za-z0-9._-]*$') {
    throw "-IpaUser must be a POSIX login name: letters, digits, dot, underscore, hyphen, not starting with a hyphen (got '$IpaUser')."
}
if ($CaSha256 -and $CaSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
    throw "-CaSha256 must be exactly 64 hex characters, the output of ``sha256sum /etc/ipa/ca.crt`` on an enrolled host (got '$CaSha256')."
}

# Validate up front rather than at step 6: the bridge speaks HTTPS with a
# Kerberos Negotiate header, so a plain-http URL would silently ship the token
# in clear. Reject anything that is not https, and normalise the trailing slash
# once so the registration and the download agree. The narrow-charset rationale
# is at $httpsUrl above.
if ($McpUrl -and -not $SkipMcp) {
    if ($McpUrl -notmatch $httpsUrl) {
        throw "-McpUrl must be an https:// URL with no shell metacharacters (got '$McpUrl')."
    }
}
$McpBase = $McpUrl.TrimEnd('/')

# -BaseUrl gets the same treatment, for a stronger reason: it is the host that
# hands a root shell inside WSL its installer. It is also fetched over plain
# Invoke-WebRequest for JsoncEdit.ps1, so http:// has to be refused here rather
# than discovered later.
if ($BaseUrl) {
    if ($BaseUrl -notmatch $httpsUrl) {
        throw "-BaseUrl must be an https:// URL with no shell metacharacters (got '$BaseUrl')."
    }
}
$BaseUrl = $BaseUrl.TrimEnd('/')

function Say($m) { Write-Host "[setup] $m" }
function Warn($m) { Write-Host "[warn ] $m" -ForegroundColor Yellow }
function Test-Admin {
    (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Get-WslDistros {
    if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) { return @() }
    @(wsl --list --quiet 2>$null | ForEach-Object { ($_ -replace "`0", '').Trim() } | Where-Object { $_ })
}
# Run a multi-line bash script in WSL. Passing it inline to wsl.exe gets mangled
# by argument parsing, so it goes via a temp file.
function Invoke-WslScript {
    param([string]$Script, [switch]$AsRoot)
    $tmp = Join-Path $env:TEMP ("wsl-setup-" + [guid]::NewGuid().ToString('N') + '.sh')
    try {
        Set-Content -Path $tmp -Value ($Script -replace "`r`n", "`n") -Encoding ascii -NoNewline
        $wslPath = '/mnt/' + $tmp.Substring(0, 1).ToLower() + ($tmp.Substring(2) -replace '\\', '/')
        if ($AsRoot) { $out = wsl -u root -e bash $wslPath } else { $out = wsl -e bash $wslPath }
        if ($LASTEXITCODE -ne 0) { throw "WSL step failed ($LASTEXITCODE): $out" }
        return $out
    } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
}

# --- 1. WSL2 (skipped entirely if a distro already exists) ------------------
$distros = @(Get-WslDistros)
if ($distros.Count -gt 0) {
    Say "WSL distro present: $($distros[0])  (install skipped)"
} elseif ($SkipWsl) {
    throw 'No WSL distro and -SkipWsl was given.'
} else {
    if (-not (Test-Admin)) {
        throw "No WSL distro found; installing one needs Administrator. Run elevated:  wsl --install -d $WslDistro   then launch it once to create your Linux user, then re-run this."
    }
    Say "installing WSL distro $WslDistro (several minutes)..."
    wsl --install -d $WslDistro --no-launch
    if ($LASTEXITCODE -ne 0) { throw "wsl --install failed ($LASTEXITCODE). A reboot may be required." }
    $distros = @(Get-WslDistros)
    if ($distros.Count -eq 0) { throw 'Distro not registered yet. Reboot, launch it once to create your Linux user, then re-run.' }
    Say "WSL distro installed: $($distros[0])"
}

# --- 2. Kerberos client inside WSL ------------------------------------------
# ticket_lifetime/renew_lifetime must be explicit: MIT's default renew_lifetime
# is 0, which makes tickets non-renewable and breaks the documented `kinit -R`.
# The ccache goes in the user's home, not /var/tmp: that directory is 1777 and
# the path is predictable, so another uid can squat the filename and lock the
# user out. It must also not be /tmp, which systemd-tmpfiles wipes on every
# boot; WSL2 shuts its VM down after ~60s idle, so that is constant.
#
# forwardable defaults to the literal `false`, which is what step 3 pairs it with
# (GSSAPIDelegateCredentials no) and what an SSH-only fleet wants.
#
# History, because this line was got wrong twice: it was once rendered by a
# PowerShell subexpression inline in the double-quoted here-string below,
# testing a $Forwardable variable that was not a parameter, so it evaluated
# $null on every run and emitted 'false' unconditionally, a security-relevant
# value that looked configurable and was not. The fix is a real parameter plus
# a pre-computed variable interpolated below. Do not put a $( ) back inside
# that here-string.
#
# What the switch means: a non-forwardable ticket cannot be delegated even by a
# client that asks to, so leaving this off makes a fleet structurally unable to
# hand its users' credentials to anything, the stronger posture and the right
# default. Turn it on only for a fleet using [D1] on-behalf-of forwarding:
# evidence-based S4U2Proxy hard-requires a forwardable caller ticket and the
# KDC refuses the whole flow without it.
#
# The trade is bounded by the server, not by this flag: forwardable also lets a
# modified client hand the MCP server a full TGT instead of a narrow evidence
# credential, but the server refuses that (delegation.is_narrow_evidence), so
# the realm's target allowlist still applies. See SECURITY.md [D1]. The shipped
# bridge never delegates either way, [CL1].
$fwd = if ($Forwardable) { 'true' } else { 'false' }
$caWant = $CaSha256.ToLower()
$bash = @"
set -e
export DEBIAN_FRONTEND=noninteractive
# Two independent prerequisites: krb5-user provides kinit for SSH, python3-gssapi
# is what the MCP bridge imports. The previous guard tested kinit only,
# so a workstation that already had krb5-user skipped the apt step entirely and
# the bridge later died with 'missing Kerberos support: install python3-gssapi'.
need=''
command -v kinit >/dev/null 2>&1 || need="`$need krb5-user"
python3 -c 'import gssapi' >/dev/null 2>&1 || need="`$need python3-gssapi"
if [ -n "`$need" ]; then
  apt-get update -qq >/dev/null 2>&1 || true
  # Deliberately unquoted so the package names word-split. The value is
  # script-literal, never user input.
  apt-get install -y -qq `$need >/tmp/krb5-install.log 2>&1 || { echo 'APT FAILED'; tail -15 /tmp/krb5-install.log; exit 1; }
fi
cat > /etc/krb5.conf <<'CONF'
[libdefaults]
    default_realm = $Realm
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    udp_preference_limit = 0
    forwardable = $fwd
    default_ccache_name = FILE:/home/%{username}/.krb5/ccache

[realms]
    $Realm = {
        kdc = $Kdc
        admin_server = $Kdc
        default_domain = $Domain
    }

[domain_realm]
    .$Domain = $Realm
    $Domain = $Realm
CONF
command -v kinit klist >/dev/null || { echo 'kinit missing'; exit 1; }
ldd /usr/bin/ssh | grep -q gssapi || { echo 'WSL ssh has no GSSAPI'; exit 1; }
# stderr must be discarded: an ImportError traceback would land in the output
# array that the caller inspects for 'OK', which is noise at best.
python3 -c 'import gssapi' >/dev/null 2>&1 || { echo 'python3-gssapi missing (the MCP bridge will not be able to authenticate)'; exit 1; }

# Realm CA into WSL's trust store. SSH does not need this (GSSAPI + host keys),
# but every HTTPS client does, and without it internal sites fail with the
# misleading 'self-signed certificate in chain'. Non-fatal: ssh must still work
# on a workstation that cannot reach the CA endpoint.
ca_step() {
  [ -f /usr/local/share/ca-certificates/realm-ca.crt ] && { echo CA-OK; return 0; }
  curl -fsS --max-time 15 -o /tmp/realm-ca.crt http://$Kdc/ipa/config/ca.crt || { echo CA-SKIP; return 0; }
  openssl x509 -in /tmp/realm-ca.crt -noout 2>/dev/null || { echo CA-SKIP; return 0; }
  # The fetch is plain HTTP, so pass -CaSha256 to make it verifiable rather than
  # trust-on-first-use. Read the value once from an enrolled host:
  #   sha256sum /etc/ipa/ca.crt
  # NOTE: this is a DOUBLE-quoted here-string, so PowerShell interpolates it and
  # the escape character is the BACKTICK, not the backslash. Every shell variable
  # below must therefore be backtick-escaped. An unescaped dollar-parenthesis is
  # a PowerShell SUBEXPRESSION: it runs on the ADMIN'S WINDOWS MACHINE while the
  # string is being built, not in WSL. This very comment used to spell that out
  # with a literal example, which meant building the string spawned cmd.exe and
  # hung any non-interactive run.
  want='$caWant'
  got=`$(sha256sum /tmp/realm-ca.crt | cut -d' ' -f1)
  # No pin means no way to tell the real CA from whatever answered port 80, so
  # installing it would be trust-on-first-use over an unauthenticated channel.
  # Leave the trust store untouched and let the caller explain the fix. Still
  # non-fatal: SSH does not need the CA.
  if [ -z "`$want" ]; then
    echo CA-UNPINNED
    return 0
  fi
  if [ "`$want" != "`$got" ]; then
    echo "CA-PIN-MISMATCH want=`$want got=`$got"
    return 1
  fi
  install -m 0644 /tmp/realm-ca.crt /usr/local/share/ca-certificates/realm-ca.crt
  update-ca-certificates >/dev/null 2>&1 && echo CA-OK || echo CA-SKIP
}
ca_step || exit 1
echo OK
"@
$wslStep2 = @(Invoke-WslScript -Script $bash -AsRoot)
if ($wslStep2 -notcontains 'OK') { throw 'WSL Kerberos provisioning failed' }
Say 'WSL: krb5-user + python3-gssapi installed, /etc/krb5.conf written (renewable, private ccache)'
if ($wslStep2 -contains 'CA-UNPINNED') {
    Warn 'realm CA NOT installed: this copy of the script carries no pinned hash.'
    Warn 'Pass -CaSha256 <sha256sum of /etc/ipa/ca.crt, taken from any enrolled host>.'
} elseif ($wslStep2 -contains 'CA-SKIP') {
    Warn "realm CA endpoint unreachable (http://$Kdc/ipa/config/ca.crt). SSH works; HTTPS to internal hosts will not until this is installed."
}

# --- 3. ssh_config inside WSL, in a sentinel-delimited managed block ---------
# Sentinels make this genuinely idempotent: re-running with a different
# -IpaUser rewrites the block instead of silently doing nothing.
$bash2 = @"
set -e
mkdir -p ~/.ssh ~/.krb5 && chmod 700 ~/.ssh ~/.krb5
touch ~/.ssh/config && chmod 600 ~/.ssh/config
sed -i '/# BEGIN setup-workstation/,/# END setup-workstation/d' ~/.ssh/config
cat >> ~/.ssh/config <<'CONF'
# BEGIN setup-workstation
Host *.$Domain
    User $IpaUser
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no
# END setup-workstation
CONF
echo OK
"@
if ((Invoke-WslScript -Script $bash2) -notcontains 'OK') { throw 'WSL ssh_config step failed' }
Say "WSL: ~/.ssh/config managed block for *.$Domain (user $IpaUser)"

# --- 4. wslssh ---------------------------------------------------------------
# A PowerShell function rather than a .bat: batch %* is re-parsed by cmd.exe, so
# an argument containing & | < > ^ becomes local command execution. @args splats
# safely with no cmd layer. The .bat exists only because VS Code's
# remote.SSH.path needs a file on disk; it is not for interactive use.
$binDir = "$env:USERPROFILE\bin"
New-Item -ItemType Directory -Force $binDir | Out-Null
$wrapper = Join-Path $binDir 'ssh-dispatch.bat'
# remote.SSH.path is global in VS Code, so this wrapper must serve both worlds:
# realm hosts go to WSL (Kerberos), everything else falls through to the native
# Windows ssh so existing Host aliases, keys and known_hosts keep working. That
# keeps the user on a single VS Code profile.
# `set "ARGS=%*"` (quoted) rather than `echo %*` so an argument containing
# & | < > is not re-parsed as cmd syntax.
Set-Content -Path $wrapper -Encoding ascii -Value @"
@echo off
REM Managed by setup.ps1 - dispatches by destination.
REM   *.$Domain            -> WSL ssh  (Kerberos/GSSAPI)
REM   everything else      -> Windows ssh.exe (your keys, aliases, known_hosts)
setlocal enabledelayedexpansion
set "ARGS=%*"
set "STRIPPED=!ARGS:.$Domain=!"
if not "!STRIPPED!"=="!ARGS!" (
    endlocal & wsl.exe -e ssh %*
) else (
    endlocal & "%SystemRoot%\System32\OpenSSH\ssh.exe" %*
)
"@
Remove-Item (Join-Path $binDir 'ssh-wsl.bat') -ErrorAction SilentlyContinue   # old name

# $PROFILE is populated by the host, so it is empty in runspaces that never load
# one: background jobs, `powershell -NonInteractive`, and most remote-management
# tooling (Intune, SCCM, PSRemoting), i.e. exactly how a fleet rollout runs this.
# Reconstruct the documented path rather than letting Join-Path throw on $null.
$profilePath = $PROFILE.CurrentUserAllHosts
if ([string]::IsNullOrWhiteSpace($profilePath)) {
    $docs = [Environment]::GetFolderPath('MyDocuments')
    if ([string]::IsNullOrWhiteSpace($docs)) { $docs = Join-Path $env:USERPROFILE 'Documents' }
    $dir = if ($PSVersionTable.PSEdition -eq 'Core') { 'PowerShell' } else { 'WindowsPowerShell' }
    $profilePath = Join-Path (Join-Path $docs $dir) 'profile.ps1'
}
New-Item -ItemType Directory -Force (Split-Path $profilePath -Parent) | Out-Null
if (-not (Test-Path $profilePath)) { New-Item -ItemType File $profilePath | Out-Null }
# @() on both sides: a single-line file makes -notmatch return a scalar boolean,
# which previously got written back over the profile as the text "False".
#
# Match on the function definition itself, not the trailing comment: a filter of
# 'setup-workstation\.ps1' stopped matching when the script was renamed to
# setup.ps1, and every re-run then appended a second `function` line. Anchoring
# on the thing being managed stays idempotent across any future rename.
#
# The alternation carries the old name too: the function was called `kssh`
# before, and profiles provisioned back then still define it. Matching only the
# current name would leave that stale `kssh` working forever, updated by
# nothing. Removing the retired name is the point of listing it: do not drop
# `kssh` here.
$kept = @(@(Get-Content -Path $profilePath) | Where-Object { $_ -notmatch '^\s*function\s+(wslssh|kssh)\b' })
$kept += "function wslssh { wsl.exe -e ssh @args }   # Kerberos ssh via WSL (setup.ps1)"
Set-Content -Path $profilePath -Value $kept -Encoding ascii
Say 'PowerShell: wslssh function added (your `ssh` is left untouched)'

# --- 5. VS Code --------------------------------------------------------------
# enableDynamicForwarding=false is deliberate. VS Code's default reaches the
# remote server through a SOCKS proxy (ssh -D) that our WSL ssh binds inside WSL's
# own network namespace. On a cold connect Windows can try to reach that port
# before WSL has mirrored it to the Windows loopback, which surfaces as
# `connect ECONNREFUSED 127.0.0.1:<port>` after the remote server has already
# started (and often as a follow-on "extension failed to launch" that is really
# just the dead connection). A plain TCP forward sidesteps that timing. It does
# not move the port out of WSL, so the durable cure is WSL mirrored networking
# (documented in client/README); this setting is the low-cost mitigation the
# installer can safely own without touching machine-wide networking.
$desired = @{
    'remote.SSH.path'                    = $wrapper
    'remote.SSH.useLocalServer'          = $false
    'remote.SSH.enableDynamicForwarding' = $false
}
if ($SkipVSCode) {
    Say 'VS Code: skipped (-SkipVSCode)'
} else {
    # JsoncEdit.ps1 is loaded here, in the only step that uses it: editing VS
    # Code's settings.json, which is JSONC and cannot be round-tripped through
    # ConvertTo-Json without destroying the user's comments and formatting.
    # Requiring it unconditionally up front made an SSH-only workstation demand
    # a helper it was never going to call. Users should only ever have to
    # download one file, so if the helper is not sitting next to this script we
    # fetch it over TLS.
    #
    # A SHA-256 of the helper was once pinned here, substituted at publish time.
    # It was removed with the rest of the signing chain and for the same reason:
    # a hash injected by the publisher into a script served by the publisher
    # only proved that host agreed with itself. Against a network attacker it
    # added nothing TLS did not already give, and against a compromised
    # publisher it added nothing at all. So this is plain TLS trust, the same
    # level install-bridge.sh gets before being run as root: one trust level
    # for everything fetched from the publisher.
    $helper = Join-Path $PSScriptRoot 'JsoncEdit.ps1'
    if (-not (Test-Path $helper)) {
        if (-not $BaseUrl) {
            throw "VS Code setup needs JsoncEdit.ps1, which is not next to this script, and no -BaseUrl was given to fetch it from. Either put JsoncEdit.ps1 beside setup.ps1, or pass -BaseUrl (e.g. https://mcp.example.internal/client when the MCP host serves the bundle, which is the default, or https://<host>/client wherever you copied an exported bundle), or pass -SkipVSCode to provision Kerberos SSH only, which needs no helper at all."
        }
        $helper = Join-Path ([IO.Path]::GetTempPath()) ("JsoncEdit-$([guid]::NewGuid().ToString('N')).ps1")
        Write-Host "[setup] fetching JsoncEdit.ps1 from $BaseUrl (TLS only, not verified further)"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/JsoncEdit.ps1" -OutFile $helper
    }
    . $helper

    $editors = @(
        @{ Name = 'VS Code'; Proc = 'Code'; Path = "$env:APPDATA\Code\User\settings.json" }
        @{ Name = 'VS Code Insiders'; Proc = 'Code - Insiders'; Path = "$env:APPDATA\Code - Insiders\User\settings.json" }
        @{ Name = 'VSCodium'; Proc = 'VSCodium'; Path = "$env:APPDATA\VSCodium\User\settings.json" }
    )
    # remote.SSH.path is global, but the wrapper dispatches, so non-realm hosts
    # still go to the native Windows ssh. Name them so the user can confirm.
    $winSshCfg = "$env:USERPROFILE\.ssh\config"
    if (Test-Path $winSshCfg) {
        $others = @(Select-String -Path $winSshCfg -Pattern '^\s*Host\s+(?!\*)' |
            ForEach-Object { ($_.Line -replace '^\s*Host\s+', '').Trim() })
        if ($others.Count -gt 0) {
            Say ("VS Code: these keep using the native Windows ssh (keys/aliases intact): " +
                (($others | Select-Object -First 8) -join ', '))
            Say "VS Code: only *.$Domain is routed through WSL. One profile, both worlds."
        }
    }
    $any = $false
    foreach ($ed in $editors) {
        $name = $ed.Name; $path = $ed.Path
        if (-not (Test-Path (Split-Path $path -Parent))) { continue }
        $any = $true
        if (Get-Process -Name $ed.Proc -ErrorAction SilentlyContinue) {
            Warn "$name is running - it may rewrite settings.json on exit; re-run if the keys do not stick."
        }
        if (Test-Path $path) {
            $orig = [IO.File]::ReadAllText($path)
            if ([string]::IsNullOrWhiteSpace($orig)) { $orig = "{`n}" }
        } else {
            New-Item -ItemType Directory -Force (Split-Path $path -Parent) | Out-Null
            $orig = "{`n}"
        }
        if (-not (Test-JsoncValid $orig)) {
            Warn "${name}: settings.json is not valid JSON/JSONC - left alone. Add manually:"
            Write-Host "    `"remote.SSH.path`": $($wrapper | ConvertTo-Json)," -ForegroundColor Cyan
            Write-Host '    "remote.SSH.useLocalServer": false,' -ForegroundColor Cyan
            Write-Host '    "remote.SSH.enableDynamicForwarding": false' -ForegroundColor Cyan
            continue
        }
        $text = $orig
        foreach ($k in $desired.Keys) {
            $val = if ($desired[$k] -is [bool]) { $desired[$k].ToString().ToLower() } else { $desired[$k] | ConvertTo-Json }
            $new = Set-JsoncKey -Text $text -Key $k -JsonValue $val
            if ($null -eq $new) { $text = $null; break }
            $text = $new
        }
        if ($null -eq $text) {
            Warn "${name}: settings.json has a shape this script will not edit blindly (key present with a non-scalar value, or no top-level object) - left alone."
        } elseif ($text -eq $orig) {
            Say "${name}: settings already correct"
        } elseif (-not (Test-JsoncValid $text)) {
            Warn "${name}: edit would produce invalid JSON - aborted, file untouched."
        } else {
            Copy-Item $path "$path.bak" -Force -ErrorAction SilentlyContinue
            [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding($false)))
            Say "${name}: settings updated (comments preserved; backup at settings.json.bak)"
        }
    }
    if (-not $any) { Say 'VS Code: not installed, skipped' }
}


# --- 6. MCP bridge (opt-in: -McpUrl) -----------------------------------------
# Claude Code runs on Windows, but the Kerberos ticket lives in WSL, so the
# bridge has to be launched through wsl.exe. That is why the registration below
# is command=wsl.exe with the interpreter and script path as arguments, and not
# command=/usr/bin/python3 like the Linux examples in bridge/examples/.
$mcpDone = $false
if ($SkipMcp) {
    Say 'MCP: skipped (-SkipMcp)'
} elseif (-not $McpBase) {
    Say 'MCP: skipped (no -McpUrl; this workstation is SSH-only)'
} else {
    # Which distro: on a machine with Docker Desktop, a bare `wsl.exe -e` targets
    # the default distro, which is frequently docker-desktop and has none of this
    # provisioning. The name is reported by the provisioned distro itself below
    # (WSL_DISTRO_NAME), not taken from `wsl --list` ordering: that list is in
    # registration order, not default order, so on a two-distro machine the
    # registration would have named a distro the earlier steps never touched.
    $distro = if ($distros.Count -gt 0) { $distros[0] } else { $WslDistro }

    # The bridge speaks HTTPS to the MCP server, so without the realm CA it would
    # fail later with an opaque certificate error. Fatal here, unlike step 2,
    # where the CA is merely nice to have.
    #
    # Every handled failure inside WSL echoes a marker and exits 0 on purpose: a
    # non-zero exit makes Invoke-WslScript throw, which would swallow the marker
    # and leave the operator with "WSL step failed (1)" and nothing to act on.
    # PowerShell reads the markers below; all of them are fatal, the marker just
    # names which thing broke.

    # Both values were charset-validated at the top of this script, which is what
    # makes single-quoting them into the here-string safe: neither can close its
    # shell word and run as root inside WSL. install-bridge.sh has no baked-in
    # host, so everything it needs is passed in here.
    $urlArgs = "--base-url '$BaseUrl' --mcp-url '$McpBase/'"

    # Refuse before anything runs as root inside WSL. Steps 1-5 are already
    # done, so SSH is provisioned either way; this is the same posture as
    # CA-MISSING below, and the same reason: -McpUrl was asked for, it cannot be
    # satisfied, and a zero exit would read as success to Intune or SCCM.
    if (-not $BaseUrl) {
        throw "MCP: -McpUrl was given but -BaseUrl was not, so there is nowhere to download the bridge from. They are two roles, not necessarily two hosts: -McpUrl is the API the bridge talks to, -BaseUrl is wherever the client files are published. The MCP host serves them itself by default, so pass -BaseUrl https://mcp.example.internal/client ; otherwise point -BaseUrl at wherever you copied an exported bundle, e.g. https://<host>/client ."
    }
    $mcpBash = @"
set -e
echo "DISTRO=`$WSL_DISTRO_NAME"
[ -f /usr/local/share/ca-certificates/realm-ca.crt ] || { echo CA-MISSING; exit 0; }
tmp=`$(mktemp -d)
trap 'rm -rf "`$tmp"' EXIT
# Fetch the installer published at -BaseUrl and run it as root.
#
# TLS is the whole of the assurance here, and the flags are what keep it that
# much: --proto '=https' refuses a redirect to plain http, --tlsv1.2 sets a
# floor, and --cacert pins the leg to the realm CA installed in step 2.
#
# None of it helps against the publisher itself. A publisher that is compromised
# serves whatever it likes and this runs it as root; that is the accepted
# posture, not an oversight. Everything below is a control on the wire, not on
# the party at the other end of it. See SECURITY.md [SC1].
#
# The pin is explicit rather than inherited from the trust store. Step 2 does
# run update-ca-certificates, so the realm CA is in the system bundle and an
# unpinned curl would succeed - but it would also succeed for any of the ~150
# public CAs Ubuntu ships, and these bytes are executed as root on the next
# line. Adding the realm CA widened the trust set for this fetch instead of
# narrowing it. Naming the file narrows it back to one issuer, which is exactly
# what client/setup.sh does with /etc/ipa/ca.crt on its own fetch of the same
# installer. -CaSha256 pinned the CA on the way in; this is what makes that pin
# mean anything for the artifact that becomes root code.
#
# No fallback to the system store here, unlike setup.sh. There, dropping the pin
# keeps a half-enrolled host from being stranded mid-ipa-client-install. Here
# steps 1-5 are already complete and SSH works, so a failure costs the operator
# a re-run and nothing else. Fail closed.
#
# The file is guaranteed present: the CA-MISSING guard above returns before this
# line when it is absent.
#
# Never install from the repo checkout on /mnt/c instead: drvfs reports 0777, so
# any local user could have rewritten those bytes, which is strictly weaker than
# an authenticated fetch from the publisher.
curl --proto '=https' --tlsv1.2 -fsS \
     --cacert /usr/local/share/ca-certificates/realm-ca.crt \
     -o "`$tmp/install-bridge.sh" '$BaseUrl/install-bridge.sh' || { echo FETCH-FAILED; exit 0; }
sh "`$tmp/install-bridge.sh" $urlArgs || { echo INSTALL-FAILED; exit 0; }
[ -f /opt/mcp-krb/mcp-krb-bridge.py ] || { echo MISSING-AFTER-INSTALL; exit 0; }
echo OK
"@
    $mcpOut = @()
    try {
        $mcpOut = @(Invoke-WslScript -Script $mcpBash -AsRoot)
    } catch {
        Warn "MCP: bridge install failed inside WSL. $_"
    }
    $reported = @($mcpOut | Where-Object { $_ -like 'DISTRO=*' })
    if ($reported.Count -gt 0) {
        $named = $reported[0].Substring(7).Trim()
        if ($named) { $distro = $named }
    }
    if ($mcpOut -contains 'CA-MISSING') {
        # Checked before the catch-all below so the operator gets the actionable
        # message: this failure has one specific fix. Fatal for the same reason
        # as everything else here; see the refusal above.
        throw "MCP: the realm CA is not in WSL's trust store, so the bridge cannot be installed over HTTPS. Fix the CA step first (pass -CaSha256, see the Realm CA section of README.md), then re-run."
    }
    if ($mcpOut -contains 'OK') {
        $mcpDone = $true
        # Claim only what this path established: the bytes came from $BaseUrl
        # over TLS, validated against the realm CA pinned in step 2.
        Say "WSL: MCP bridge installed to /opt/mcp-krb (fetched over TLS from $BaseUrl)"
    } elseif ($mcpOut.Count -gt 0) {
        # Fatal for the same reason as CA-MISSING: a zero exit would read as
        # success to Intune or SCCM while /opt/mcp-krb is absent or stale. This
        # used to be a Warn plus exit 0, which is how a failed install reported
        # clean across a whole fleet.
        throw "MCP: the bridge install did not complete and /opt/mcp-krb was NOT updated. Markers from WSL: $($mcpOut -join '; '). Steps 1-5 (SSH/Kerberos) did complete. Fix the cause and re-run; nothing else on this machine depends on it."
    } else {
        throw "MCP: the bridge install produced no output at all from WSL, so nothing can be said about whether it ran. /opt/mcp-krb was NOT confirmed. Steps 1-5 (SSH/Kerberos) did complete."
    }
}

if ($mcpDone) {
    # Strict JSON, built by ConvertTo-Json so quoting and escaping cannot drift.
    $mcpEntry = @{
        mcpServers = @{
            'internal-tools' = @{
                type    = 'stdio'
                command = 'wsl.exe'
                args    = @('-d', $distro, '-e', '/usr/bin/python3',
                            '/opt/mcp-krb/mcp-krb-bridge.py', "$McpBase/")
            }
        }
    }
    $mcpJson = $mcpEntry | ConvertTo-Json -Depth 6 -Compress
    $claudeCli = Get-Command claude -ErrorAction SilentlyContinue
    $registered = $false
    if ($claudeCli) {
        # Windows PowerShell 5.1 wraps a native command's stderr in an ErrorRecord
        # when it is redirected, and ErrorActionPreference=Stop then turns an
        # ordinary "not found" exit into a terminating NativeCommandError.
        # Relax it around the CLI calls and branch on the exit code instead.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            # Probe first: an existing entry may have been tuned by hand, and the
            # CLI owns the file. %USERPROFILE%\.claude.json also holds unrelated
            # session state, so it is never edited directly here.
            & claude mcp get internal-tools 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Say 'MCP: internal-tools is already registered - left untouched'
                $registered = $true
            } else {
                & claude mcp add-json --scope user internal-tools $mcpJson 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Say 'MCP: registered internal-tools for your user (via wsl.exe)'
                    $registered = $true
                } else {
                    Warn 'MCP: `claude mcp add-json` failed - register manually:'
                }
            }
        } finally { $ErrorActionPreference = $prevEap }
    } else {
        Warn 'MCP: the `claude` CLI is not on PATH - register manually:'
    }
    if (-not $registered) {
        Write-Host "    claude mcp add-json --scope user internal-tools '$mcpJson'" -ForegroundColor Cyan
    }
}

Write-Host ''
Say 'Done. In a NEW terminal:'
Write-Host "    wsl kinit $IpaUser@$Realm" -ForegroundColor Green
Write-Host "    wslssh anything.$Domain" -ForegroundColor Green
if ($mcpDone) {
    Write-Host "    claude mcp list                  # internal-tools should be listed" -ForegroundColor Green
}
Write-Host ''
Say 'Your existing `ssh`, keys, host aliases and known_hosts are untouched.'
if ($mcpDone) {
    Say 'MCP calls use the same ticket as SSH: if they start failing, run `wsl kinit -R`.'
}
