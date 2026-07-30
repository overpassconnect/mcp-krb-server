#!/bin/sh
# Provision a Mac for realm SSO and the MCP bridge.
#
# The macOS counterpart to setup.sh and setup.ps1. Run it, then kinit, and the
# machine has realm SSO and the MCP bridge.
#
# HOW FAR THIS IS PROVEN, so you can judge it rather than trust it. Steps 1 to 4
# automate the manual procedure this repo has shipped and served for months,
# which was worked out on a live Mac; the logic is not speculative. Step 5, the
# bridge, is newer and rests on the wheel analysis in client/README.md: every
# extension module in python-gssapi's macOS wheels links the system
# GSS.framework, so the bridge and kinit share one credential cache. Syntax,
# both embedded python blocks and the whole --dry-run path are checked in CI.
#
# Not yet exercised end to end on hardware: that `security add-trusted-cert` and
# `python3 -m venv` behave as documented on your OS release. Both are step-local
# and both report failure loudly. Use --dry-run first if you want to read the
# plan before anything changes.
#
# What it does, and what it deliberately does not:
#
#   does      split DNS, krb5.conf, ~/.ssh/config, optional realm CA, the MCP
#             bridge, MCP registration, and an install manifest for uninstall
#   does not  enrol the machine in FreeIPA. A Mac cannot run ipa-client-install,
#             so this is a Kerberos client configuration and nothing more. The
#             realm never learns this machine exists, which is also why macOS
#             genuinely leaves FreeIPA untouched where Linux does not.
#
# Usage:
#   sh setup-macos.sh --domain example.internal --realm EXAMPLE.INTERNAL \
#       --kdc ipa.example.internal --dns-ip 10.0.0.53 --ipa-user jdoe \
#       [--mcp-url https://mcp.example.internal/] [--base-url URL] \
#       --ca-sha256 HEX [--skip-mcp] [--managed] [--dry-run]
#
#   --managed  register machine-wide in /Library/Application Support/ClaudeCode/
#              managed-mcp.json instead of the user's ~/.claude.json. Mirrors
#              install-bridge.sh --managed on Linux. Takes EXCLUSIVE control:
#              users can then add no MCP servers of their own.

set -eu

DOMAIN=''; REALM=''; KDC=''; DNS_IP=''; IPA_USER=''
MCP_URL=''; BASE_URL=''; CA_SHA=''
SKIP_MCP=0; DRY_RUN=0; MANAGED=0
CERT_SHA1=''

die() { echo "error: $*" >&2; exit 1; }
say() { echo "  $*"; }
run() {
    if [ "$DRY_RUN" = 1 ]; then echo "  would run: $*"; else "$@"; fi
}

usage() { sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --domain)     DOMAIN="$2"; shift 2 ;;
        --realm)      REALM="$2"; shift 2 ;;
        --kdc)        KDC="$2"; shift 2 ;;
        --dns-ip)     DNS_IP="$2"; shift 2 ;;
        --ipa-user)   IPA_USER="$2"; shift 2 ;;
        --mcp-url)    MCP_URL="$2"; shift 2 ;;
        --base-url)   BASE_URL="$2"; shift 2 ;;
        --ca-sha256)  CA_SHA="$2"; shift 2 ;;
        --skip-mcp)   SKIP_MCP=1; shift ;;
        --managed)    MANAGED=1; shift ;;
        --dry-run)    DRY_RUN=1; shift ;;
        -h|--help)    usage ;;
        *)            die "unknown argument: $1" ;;
    esac
done

# ---------------------------------------------------------------- preflight
# --dry-run is allowed off-Darwin on purpose, so the whole control flow can be
# exercised on any machine. Anything that actually mutates is still gated.
if [ "$(uname -s)" != Darwin ]; then
    [ "$DRY_RUN" = 1 ] || die "this is the macOS script; on Linux use setup.sh"
    echo "note: not macOS, so this is a dry run of the logic only" >&2
fi
[ -n "$DOMAIN" ]   || die "--domain is required"
[ -n "$REALM" ]    || die "--realm is required"
[ -n "$KDC" ]      || die "--kdc is required"
[ -n "$DNS_IP" ]   || die "--dns-ip is required"
[ -n "$IPA_USER" ] || die "--ipa-user is required"
# Required, not optional. The bridge speaks HTTPS to the MCP host, and
# without the realm CA that fails with an opaque certificate error that
# looks like a bug in the bridge. Get the hash from whoever runs the realm,
# out of band: the certificate is fetched over plain HTTP, so comparing it
# against a hash from the same infrastructure would be checking it against
# itself.
[ -n "$CA_SHA" ]   || die "--ca-sha256 is required. Ask whoever runs the realm
  for the SHA-256 of its CA, and do not take it from the provisioning page."

command -v python3 >/dev/null || die "python3 not found; run: xcode-select --install"
if [ "$DRY_RUN" != 1 ]; then
    command -v kinit >/dev/null || die "kinit not found, which should be impossible on macOS"
fi

SUDO=sudo
[ "$(id -u)" = 0 ] && SUDO=''

APPDIR="$HOME/Library/Application Support/mcp-krb"
MANIFEST="$APPDIR/install-manifest.json"
CREATED=''
CREATED_DIRS=''
REPLACED=''

note_created()     { CREATED="$CREATED $1"; }
note_created_dir() { CREATED_DIRS="$CREATED_DIRS $1"; }
note_replaced()    { REPLACED="$REPLACED $1"; }

echo "==> provisioning for $REALM"

# ------------------------------------------------------- 1. split DNS
# macOS only. mDNSResponder sends lookups for this one domain to the realm
# resolver and leaves the rest of DNS alone, so a coffee-shop network still
# works. Only A records matter here: the KDC is pinned below, not discovered.
echo "==> 1. split DNS"
RESOLVER="/etc/resolver/$DOMAIN"
if [ -f "$RESOLVER" ] && grep -q "nameserver $DNS_IP" "$RESOLVER" 2>/dev/null; then
    say "$RESOLVER already correct"
else
    run $SUDO mkdir -p /etc/resolver
    if [ "$DRY_RUN" = 1 ]; then
        say "would write $RESOLVER"
    else
        printf 'nameserver %s\n' "$DNS_IP" | $SUDO tee "$RESOLVER" >/dev/null
        note_created "$RESOLVER"
        say "wrote $RESOLVER"
    fi
fi

# ------------------------------------------------------- 2. Kerberos
# The tcp/ prefix is the whole ballgame. macOS ships Heimdal, which has no
# udp_preference_limit. Over UDP the KDC issues the ticket and the oversized
# reply is dropped by any small-MTU VPN, so the client reports "unable to reach
# any KDC in realm" about a KDC that already answered.
#
# default_ccache_name is deliberately NOT set. macOS defaults to KCM: before
# Sonoma and API: after, both session-wide, which is what lets a Dock-launched
# VS Code see the ticket. Pinning a FILE: ccache to match the WSL config would
# break GUI launches and the failure would look unrelated.
echo "==> 2. Kerberos client"
if [ "$DRY_RUN" = 1 ]; then
    say "would back up any existing /etc/krb5.conf, then write kdc = tcp/$KDC"
else
    mkdir -p "$APPDIR"
    # Back up the original exactly once. A second run must not overwrite the
    # pristine copy with our own, which is the trap setup.ps1 fell into on WSL.
    if [ -f /etc/krb5.conf ]; then
        if [ ! -f "$APPDIR/krb5.conf.orig" ]; then
            $SUDO cp -p /etc/krb5.conf "$APPDIR/krb5.conf.orig"
            note_replaced /etc/krb5.conf
            say "kept the original at $APPDIR/krb5.conf.orig"
        else
            say "original already backed up, not overwriting it"
        fi
    fi
    $SUDO tee /etc/krb5.conf >/dev/null <<CONF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = false

[realms]
    $REALM = {
        kdc = tcp/$KDC
        admin_server = $KDC
        default_domain = $DOMAIN
    }

[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
CONF
    say "wrote /etc/krb5.conf (kdc = tcp/$KDC, forwardable = false)"
fi

# ------------------------------------------------------- 3. SSH
# Delegation stays off: a non-forwardable ticket cannot be delegated even by a
# client that asks to, which pairs with forwardable = false above. SECURITY.md [CL1].
echo "==> 3. SSH over GSSAPI"
SSHCFG="$HOME/.ssh/config"
BEGIN='# BEGIN mcp-krb-setup'
END='# END mcp-krb-setup'
if [ "$DRY_RUN" = 1 ]; then
    say "would add a $BEGIN block to $SSHCFG"
else
    mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
    [ -f "$SSHCFG" ] || { : > "$SSHCFG"; note_created "$SSHCFG"; }
    chmod 600 "$SSHCFG"
    # Replace our own block only. Anything the user wrote is untouched.
    tmp=$(mktemp)
    awk -v b="$BEGIN" -v e="$END" '
        $0 == b {skip=1} !skip {print} $0 == e {skip=0}
    ' "$SSHCFG" > "$tmp"
    {
        cat "$tmp"
        printf '%s\n' "$BEGIN"
        printf 'Host *.%s\n' "$DOMAIN"
        printf '    User %s\n' "$IPA_USER"
        printf '    GSSAPIAuthentication yes\n'
        printf '    GSSAPIDelegateCredentials no\n'
        printf '%s\n' "$END"
    } > "$SSHCFG"
    rm -f "$tmp"
    say "sentinel block for *.$DOMAIN in $SSHCFG"
fi

# ------------------------------------------------------- 4. realm CA
# kinit and ssh do not need this; GSSAPI and host keys carry those. The bridge
# does, because it speaks HTTPS to the MCP host, and without the CA that fails
# with a certificate error reading like a bug in the bridge.
#
# The fetch is plain HTTP, so the hash comparison IS the check. That is why the
# expected value has to reach the operator from somewhere other than the
# infrastructure serving the certificate.
echo "==> 4. realm CA"
    ca=$(mktemp)
    curl -fsS -o "$ca" "http://$KDC/ipa/config/ca.crt" || die "could not fetch the CA"
    got=$(shasum -a 256 "$ca" | awk '{print $1}')
    if [ "$got" != "$CA_SHA" ]; then
        rm -f "$ca"
        die "CA hash mismatch. expected $CA_SHA, got $got. Stop and talk to IT."
    fi
    say "hash verified: $got"
    run $SUDO security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain "$ca"
    # Record the SHA-1, not the SHA-256 just verified. They are different hashes
    # of the same file and uninstall needs the SHA-1: `security delete-certificate
    # -Z` matches on SHA-1 only, and handing it a SHA-256 matches nothing while
    # looking like it worked, leaving the CA trusted forever.
    if [ "$DRY_RUN" != 1 ]; then
        CERT_SHA1=$(openssl x509 -noout -fingerprint -sha1 -in "$ca" \
                    | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')
        say "recorded for removal (SHA-1): $CERT_SHA1"
    fi
    rm -f "$ca"

# ------------------------------------------------------- 5. the MCP bridge
# python-gssapi ships macOS wheels for x86_64 and arm64, so no compiler is
# needed, and every extension links /System/Library/Frameworks/GSS.framework.
# That is the same Heimdal behind kinit, so the bridge reads the ticket from
# whichever session cache kinit put it in. A venv rather than pip --user because
# a system python3 may be marked externally-managed (PEP 668).
echo "==> 5. MCP bridge"
if [ "$SKIP_MCP" = 1 ] || [ -z "$MCP_URL" ]; then
    say "skipped (no --mcp-url given)"
else
    [ -n "$BASE_URL" ] || die "--mcp-url needs --base-url to fetch the bridge from"
    if [ "$DRY_RUN" = 1 ]; then
        say "would create $APPDIR/venv, pip install gssapi, fetch the bridge"
        if [ "$MANAGED" = 1 ]; then
            say "would register machine-wide in /Library/Application Support/ClaudeCode/managed-mcp.json"
        else
            say "would register for this user in ~/.claude.json (NOT the Claude Desktop app config)"
        fi
    else
        mkdir -p "$APPDIR"; note_created_dir "$APPDIR"
        [ -d "$APPDIR/venv" ] || python3 -m venv "$APPDIR/venv"
        "$APPDIR/venv/bin/pip" install --quiet --upgrade pip
        "$APPDIR/venv/bin/pip" install --quiet gssapi
        curl --proto '=https' --tlsv1.2 -fsS "$BASE_URL/mcp-krb-bridge.py" \
            -o "$APPDIR/mcp-krb-bridge.py"
        chmod 0755 "$APPDIR/mcp-krb-bridge.py"
        note_created "$APPDIR/mcp-krb-bridge.py"
        say "bridge at $APPDIR/mcp-krb-bridge.py"

        PY="$APPDIR/venv/bin/python3"
        ENTRY="{\"type\":\"stdio\",\"command\":\"$PY\",\"args\":[\"$APPDIR/mcp-krb-bridge.py\",\"$MCP_URL\"]}"

        # Three different files could be meant here and only one is Claude Code's.
        # Getting this wrong registers the server somewhere nothing reads:
        #
        #   ~/.claude.json                                          Claude Code, per user
        #   /Library/Application Support/ClaudeCode/managed-mcp.json  Claude Code, whole machine
        #   ~/Library/Application Support/Claude/claude_desktop_config.json
        #                                                           Claude DESKTOP, a different app
        #
        # Claude Code does not read the Desktop file. If someone uses the Desktop
        # chat app they need `claude mcp add-from-claude-desktop`, not this script.
        if [ "$MANAGED" = 1 ]; then
            MANAGED_DIR='/Library/Application Support/ClaudeCode'
            MANAGED_FILE="$MANAGED_DIR/managed-mcp.json"
            if [ -f "$MANAGED_FILE" ]; then
                say "$MANAGED_FILE exists; refusing to overwrite a fleet policy"
            else
                $SUDO mkdir -p "$MANAGED_DIR"
                printf '{\n  "mcpServers": {\n    "internal-tools": %s\n  }\n}\n' "$ENTRY" \
                    | $SUDO tee "$MANAGED_FILE" >/dev/null
                $SUDO chmod 0644 "$MANAGED_FILE"
                note_created "$MANAGED_FILE"
                say "machine-wide policy at $MANAGED_FILE"
                say "note: a managed file takes EXCLUSIVE control; users cannot add their own"
            fi
        elif command -v claude >/dev/null; then
            claude mcp add-json --scope user internal-tools "$ENTRY" >/dev/null 2>&1 \
                && say "registered with the claude CLI" \
                || say "claude mcp add-json failed; register by hand"
        else
            # Same fallback setup.ps1 uses when the CLI is absent: write the
            # user config directly, refusing to touch a malformed file and
            # never overwriting an entry that already exists.
            APPDIR="$APPDIR" MCP_URL="$MCP_URL" PY="$PY" python3 - <<'PYEOF'
import json, os, pathlib, shutil
cfg = pathlib.Path.home() / ".claude.json"
entry = {"type": "stdio",
         "command": os.environ["PY"],
         "args": [os.path.join(os.environ["APPDIR"], "mcp-krb-bridge.py"),
                  os.environ["MCP_URL"]]}
if cfg.exists():
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
    except Exception:
        raise SystemExit("  .claude.json is not valid JSON; left untouched")
    shutil.copy2(cfg, str(cfg) + ".bak")
else:
    data = {}
servers = data.setdefault("mcpServers", {})
if "internal-tools" in servers:
    print("  .claude.json already has internal-tools; left as is")
else:
    servers["internal-tools"] = entry
    cfg.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print("  registered in ~/.claude.json")
PYEOF
        fi
    fi
fi

# ------------------------------------------------------- 6. manifest
# So uninstall can restore rather than guess. Same contract as commit 2: a null
# prior value means the key was absent and should be deleted; a string means it
# was the user's own and should be put back.
if [ "$DRY_RUN" != 1 ]; then
    mkdir -p "$APPDIR"
    CREATED="$CREATED" CREATED_DIRS="$CREATED_DIRS" REPLACED="$REPLACED" \
    APPDIR="$APPDIR" CERT_SHA1="$CERT_SHA1" MANIFEST="$MANIFEST" python3 - <<'PYEOF'
import json, os
appdir = os.environ["APPDIR"]

# Merge with any manifest already here rather than replacing it. A second run
# finds most things already in their desired state and so records almost
# nothing, and overwriting would leave uninstall knowing less than it did after
# the first run: the resolver file, the ssh config, the certificate would all
# quietly stop being removable.
old = {}
try:
    with open(os.environ["MANIFEST"]) as f:
        prev = json.load(f)
    if prev.get("manifest_version") == 1:
        old = prev
except (OSError, ValueError):
    pass


def union(key, extra):
    seen = list(old.get(key, []))
    for v in extra:
        if v not in seen:
            seen.append(v)
    return seen


replaced = dict(old.get("replaced", {}))
replaced.update({p: os.path.join(appdir, "krb5.conf.orig")
                 for p in os.environ["REPLACED"].split()})

m = {"manifest_version": 1,
     "written_by": "setup-macos.sh",
     "created": union("created", os.environ["CREATED"].split()),
     "created_dirs": union("created_dirs", os.environ["CREATED_DIRS"].split()),
     "replaced": replaced,
     "packages_installed": [],
     "packages_already_present": [],
     "prior_values": {}}
# Not a path, so it is not in "created": removing it is a keychain operation,
# and it needs the SHA-1 rather than the SHA-256 the download was checked with.
if os.environ.get("CERT_SHA1"):
    m["trusted_cert_sha1"] = os.environ["CERT_SHA1"]
with open(os.environ["MANIFEST"], "w") as f:
    json.dump(m, f, indent=2)
print("  manifest at", os.environ["MANIFEST"])
PYEOF
fi

echo
echo "==> done. Get a ticket:"
echo "      kinit $IPA_USER@$REALM"
echo "      klist -v          # -v is the Heimdal spelling; klist -f is MIT's"
echo
echo "    Then ssh anything.$DOMAIN with no password."
echo "    VS Code Remote-SSH needs no configuration on macOS: the system ssh"
echo "    already speaks GSSAPI, unlike Windows where it must cross into WSL."
