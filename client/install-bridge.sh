#!/bin/sh
# install-bridge.sh - fetch the MCP Kerberos bridge from the publisher and
# install it atomically. Run as root or with sudo, on a host that is already
# IPA-enrolled.
#
#   curl -fsS https://mcp.example.internal/client/install-bridge.sh -o /tmp/i.sh
#   sh /tmp/i.sh --base-url https://mcp.example.internal/client \
#                --mcp-url  https://mcp.example.internal/
#
#   ... --managed             # + fleet-register the bridge machine-wide
#
# A separate file because it has three callers: client/setup.sh (straight
# after ipa-client-install), client/setup.ps1 (Windows, which runs it inside
# WSL), and a human on a box that is already enrolled. Do not fold it into
# setup.sh.
#
# Two URLs, two roles; they may be the same host:
#   --base-url  the publisher directory serving install-bridge.sh and the
#               bridge .py.
#   --mcp-url   the Kerberized MCP API the installed bridge talks to; written
#               into the client registration.
#
# They are separate decisions even when they name the same host. The MCP host
# serves the client bundle at CLIENT_PATH (default /client/), so in a normal
# install --base-url is https://<mcp-host>/client; with run.sh
# --no-serve-client the bundle is served from wherever you copied an exported
# copy. The API host is never assumed to be a download source: the download
# directory is always named explicitly.
#
# What authenticates the bytes: TLS, and nothing else. The realm CA is at
# /etc/ipa/ca.crt on an enrolled Linux host, or at
# /usr/local/share/ca-certificates/realm-ca.crt on any machine that installed it
# by hand (every Windows and macOS workstation, since only Linux can enrol), and
# the download below is pinned to it with curl --cacert, so only a certificate
# issued by the realm CA is accepted for the publisher. When the MCP host serves the bundle itself the pin still
# holds: its certificate is issued by the realm CA through the FreeIPA ACME
# service (verified on a live host). When the pin cannot apply, because the
# file is missing or the publisher's certificate does not chain to it, the
# fetch falls back to the system trust store and warns; after that fallback
# any publicly trusted CA can vouch for the publisher.
#
# There is no signature over anything here. Whoever controls --base-url
# decides which bytes land in $DEST and run as root here, and then in every
# Claude Code session on this machine. Signing on the serving host would not
# close this: a key held by the publisher authenticates exactly the party TLS
# already authenticated. This script also cannot establish its own
# authenticity, since anyone who can serve it can serve a different one. If a
# compromised publisher is in your threat model, build a signed RPM somewhere
# the serving host cannot reach, and install it from an internal repo
# (SECURITY.md [SC1]); this is the fallback path.
#
# Pure Python, no dependency install (python3-gssapi ships with ipa-client).
# Idempotent.
set -eu

BASE=""
MCP_URL=""
DEST="/opt/mcp-krb"
MANAGED_FILE="/etc/claude-code/managed-mcp.json"

BRIDGE="mcp-krb-bridge.py"
# The other two halves of the same kit. The remote bridge is what an MCP client
# on a host with no ticket talks to, and mcp-fetch picks between the two without
# the caller having to know which kind of machine this is. Installed everywhere
# rather than conditionally: a workstation today is somebody's shared dev host
# next month, and a missing file is a worse discovery than an unused one.
REMOTE="mcp-krb-remote-bridge.py"
FETCH="mcp-fetch"
FETCH_LINK="/usr/local/bin/mcp-fetch"
# The one command an MCP client is pointed at. It picks the local or the remote
# bridge at spawn time by whether the forwarded socket is present, exactly as
# mcp-fetch does, so the managed-mcp.json entry is the same on a workstation and
# on a shared host. Installed everywhere for the same reason as the remote bridge.
LAUNCH="mcp-krb"
MANIFEST="$DEST/install-manifest.json"

# --- install manifest ---------------------------------------------------------
# An uninstaller with no record of the prior state can only leave things behind
# or delete things it did not install, so every installer records what it
# actually changed. The record is a merge, not an overwrite: a re-run adds to
# it, and the first record of a replaced file or a prior value always wins,
# because only the first run saw the machine as the user had it.
#
# merge_manifest <path> <json-fragment> folds a fragment into the manifest at
# <path>, creating it if absent. Rules, each load-bearing for uninstall:
#   - created / created_dirs merge as sets: only what an installer created may
#     ever be removed.
#   - a package first recorded as already-present is never moved to installed,
#     so uninstall can never remove a package the machine already had.
#   - replaced and prior_values keep the first record: the backup of the
#     pristine original must not be re-pointed at a later copy.
# A manifest that exists but does not parse is refused, never overwritten: a
# corrupt record is still evidence, and silently replacing it would turn the
# next uninstall into guesswork.
#
# Callable standalone as `install-bridge.sh --manifest-merge <path> <fragment>`
# so setup.sh (and the tests) reuse this one implementation instead of growing
# their own with drifting rules. Standalone mode runs unprivileged; the install
# flow below sets MERGE_SUDO because $DEST is root-owned.
MERGE_SUDO=""
merge_manifest() {
    $MERGE_SUDO python3 - "$1" "$2" <<'PY'
import json, os, sys

path, frag_text = sys.argv[1], sys.argv[2]
try:
    frag = json.loads(frag_text)
except ValueError as exc:
    sys.stderr.write('manifest: fragment is not JSON: %s\n' % exc)
    sys.exit(1)
doc = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            doc = json.load(f)
    except ValueError as exc:
        sys.stderr.write('manifest: %s exists but is not JSON (%s) - '
                         'refusing to overwrite it\n' % (path, exc))
        sys.exit(1)
doc.setdefault('manifest_version', 1)
if 'written_by' in frag:
    doc['written_by'] = frag['written_by']
for key in ('created', 'created_dirs'):
    have = list(doc.get(key, []))
    for item in frag.get(key, []):
        if item not in have:
            have.append(item)
    doc[key] = have
# Only packages_installed may ever be removed by uninstall, so an entry moves
# between the two lists in one direction only: already-present never becomes
# installed. The reverse guard keeps a package this kit installed on run one
# from being re-classified as already-present by run two, which would strand it.
already = list(doc.get('packages_already_present', []))
installed = list(doc.get('packages_installed', []))
for p in frag.get('packages_already_present', []):
    if p not in already and p not in installed:
        already.append(p)
for p in frag.get('packages_installed', []):
    if p not in installed and p not in already:
        installed.append(p)
doc['packages_already_present'] = already
doc['packages_installed'] = installed
# First record wins: the backup taken before the first clobber is the pristine
# original, and the value seen before the first edit is the user's own. A JSON
# null in prior_values means the key was absent, so uninstall deletes it; a
# string is the user's value, restored verbatim.
for key in ('replaced', 'prior_values'):
    have = dict(doc.get(key, {}))
    for k, v in frag.get(key, {}).items():
        if k not in have:
            have[k] = v
    doc[key] = have
tmp = path + '.tmp'
with open(tmp, 'w') as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write('\n')
os.chmod(tmp, 0o644)
os.replace(tmp, path)
PY
}

MANAGED=0
while [ $# -gt 0 ]; do
    case "$1" in
        --managed) MANAGED=1 ;;
        # Explicit arity checks: under `set -u` a bare flag at the end of the
        # line would die with "$2: unbound variable" instead of a usage hint.
        --base-url)
            [ $# -ge 2 ] || { echo "ERROR: --base-url needs a value" >&2; exit 2; }
            BASE="$2"; shift ;;
        --base-url=*) BASE="${1#--base-url=}" ;;
        --mcp-url)
            [ $# -ge 2 ] || { echo "ERROR: --mcp-url needs a value" >&2; exit 2; }
            MCP_URL="$2"; shift ;;
        --mcp-url=*) MCP_URL="${1#--mcp-url=}" ;;
        --manifest-merge)
            # Standalone entry point for merge_manifest; used by setup.sh after
            # enrolment and by the unit tests. Exits here, before the
            # --base-url/--mcp-url requirements, because merging a manifest
            # downloads nothing and talks to nothing.
            [ $# -ge 3 ] || { echo "ERROR: --manifest-merge needs <manifest-path> <json-fragment>" >&2; exit 2; }
            merge_manifest "$2" "$3"
            exit $? ;;
        -h|--help)
            echo "usage: sh install-bridge.sh --base-url URL --mcp-url URL [--managed]"
            echo ""
            echo "  --base-url  publisher directory the bytes come FROM. Required, no"
            echo "              default, must be https://."
            echo "  --mcp-url   Kerberized MCP API the bridge TALKS TO, written into"
            echo "              the registration. Required, no default, must be"
            echo "              https://. It may be the same host as --base-url or a"
            echo "              different one: that is a server-side install choice."
            echo "  --managed   also register the bridge machine-wide in"
            echo "              $MANAGED_FILE."
            echo ""
            echo "The download is pinned to the realm CA (/etc/ipa/ca.crt on an"
            echo "enrolled Linux host, else /usr/local/share/ca-certificates/realm-ca.crt)"
            echo "when present, and warns loudly when it has to fall back to the"
            echo "system trust store. There is no signature: whoever can serve"
            echo "--base-url decides what runs as root here and in every Claude"
            echo "Code session on this machine." 
            exit 0 ;;
        *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -n "$BASE" ] || {
    echo "ERROR: --base-url is required (the directory these files are" >&2
    echo "       published under, e.g. https://mcp.example.internal/client when the" >&2
    echo "       MCP host serves the bundle, or https://<host>/client wherever you" >&2
    echo "       copied an exported bundle)." >&2
    exit 2; }
[ -n "$MCP_URL" ] || {
    echo "ERROR: --mcp-url is required (the MCP API the bridge will talk to)." >&2
    exit 2; }

case "$BASE" in
    https://*) ;;
    *) echo "ERROR: --base-url must start with https:// (got: $BASE)" >&2; exit 2 ;;
esac
BASE="${BASE%/}"

# The MCP URL is interpolated into the JSON registration below, so a quote or a
# backslash in it would break out of the string it is written into. Validate the
# shape once, here, rather than escaping at every use. Same reasoning and the
# same charset as setup.ps1's -McpUrl check.
case "$MCP_URL" in
    https://*) ;;
    *) echo "ERROR: --mcp-url must start with https:// (got: $MCP_URL)" >&2; exit 2 ;;
esac
if printf '%s' "$MCP_URL" | grep -q '[^A-Za-z0-9:/._~-]'; then
    echo "ERROR: --mcp-url contains characters that are not legal here (got: $MCP_URL)." >&2
    echo "       Allowed: letters, digits and : / . _ ~ -" >&2
    exit 2
fi

SUDO=""; [ "$(id -u)" != "0" ] && SUDO="sudo"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# Pin the TLS leg to the realm CA. Two locations, because there are two kinds of
# host. Only a Linux host can be IPA-enrolled, and only then does it have
# /etc/ipa/ca.crt. Everything else, every Windows and macOS workstation, and any
# Linux box not enrolled, has the CA installed by hand at
# /usr/local/share/ca-certificates/realm-ca.crt by setup.ps1/setup.sh. That is
# the common case for this installer, not an exception. Prefer the enrolled path
# when present, fall back to the manually-installed one, and only warn when
# neither exists. Before, this looked solely at /etc/ipa/ca.crt and warned on
# every non-enrolled machine even though the pinned CA was sitting right there,
# and the warning went to stderr where a Stop-mode PowerShell caller turned it
# into a fatal error.
CURL_CA=""
CA_PIN_DROPPED=0
if [ -r /etc/ipa/ca.crt ]; then
    CURL_CA="--cacert /etc/ipa/ca.crt"
elif [ -r /usr/local/share/ca-certificates/realm-ca.crt ]; then
    CURL_CA="--cacert /usr/local/share/ca-certificates/realm-ca.crt"
else
    echo "WARNING: no realm CA found (looked at /etc/ipa/ca.crt and" >&2
    echo "         /usr/local/share/ca-certificates/realm-ca.crt), so the realm CA" >&2
    echo "         pin is NOT in force for the download below. It falls back to the" >&2
    echo "         system trust store, where any publicly trusted CA can vouch for" >&2
    echo "         the publisher. Install the realm CA first (setup.ps1/setup.sh do" >&2
    echo "         this with -CaSha256), then re-run." >&2
fi

# shellcheck disable=SC2086  # CURL_CA is script-literal and must word-split
fetch() {
    # $1 = name under $BASE, $2 = output path
    if curl --proto '=https' --tlsv1.2 -fsS --max-time 60 $CURL_CA -o "$2" "$BASE/$1"; then
        return 0
    fi
    [ -n "$CURL_CA" ] || return 1
    # Distinguish "the realm CA does not sign this host" from "the host is down"
    # by retrying once with the system trust store. Announce it: the realm CA
    # pin is the only control on these bytes, and it just stopped applying.
    if curl --proto '=https' --tlsv1.2 -fsS --max-time 60 -o "$2" "$BASE/$1"; then
        if [ "$CA_PIN_DROPPED" = 0 ]; then
            echo "WARNING: $BASE/$1 does not validate against the realm CA" >&2
            echo "         (/etc/ipa/ca.crt). THE REALM CA PIN IS NOT IN FORCE for this" >&2
            echo "         download. It fell back to the system trust store, so any" >&2
            echo "         publicly trusted CA can vouch for the publisher, and nothing" >&2
            echo "         else checks these bytes." >&2
            CA_PIN_DROPPED=1
        fi
        CURL_CA=""
        return 0
    fi
    return 1
}

fetch_retry() {
    # $1 = name under $BASE, $2 = output path. Three attempts; transient only.
    _a=1
    while [ "$_a" -le 3 ]; do
        if fetch "$1" "$2"; then return 0; fi
        echo "WARNING: attempt $_a of 3 failed to fetch $BASE/$1" >&2
        _a=$((_a + 1))
        if [ "$_a" -le 3 ]; then sleep 5; fi
    done
    return 1
}

for f in "$BRIDGE" "$REMOTE" "$FETCH" "$LAUNCH"; do
    fetch_retry "$f" "$tmp/$f" || {
        echo "ERROR: could not fetch $BASE/$f - nothing was installed." >&2
        echo "  If this ran as part of enrolment, the IPA join may have SUCCEEDED while" >&2
        echo "  the MCP client shim was NOT installed. Finish by hand once the" >&2
        echo "  publisher is reachable:" >&2
        echo "    sh $0 --base-url $BASE --mcp-url $MCP_URL" >&2
        exit 1; }
done

# Install atomically: `install` writes via a temp file and renames, so a
# concurrent exec never sees a half-written bridge, and re-running just replaces
# it. Whether $DEST existed is checked first because only a directory this run
# created may be recorded as removable in the manifest.
DEST_EXISTED=0; [ -d "$DEST" ] && DEST_EXISTED=1
$SUDO mkdir -p "$DEST"
for f in "$BRIDGE" "$REMOTE" "$FETCH" "$LAUNCH"; do
    $SUDO install -m 0755 "$tmp/$f" "$DEST/$f"
done

# mcp-fetch is a command people type, so it goes on PATH. A symlink rather than
# a copy: the wrapper locates its siblings by directory, and two copies drifting
# apart is the failure this avoids. Only a link this run created is recorded as
# removable, so an existing mcp-fetch belonging to something else survives
# uninstall.
FETCH_LINKED=0
if [ -e "$FETCH_LINK" ] || [ -L "$FETCH_LINK" ]; then
    if [ "$(readlink "$FETCH_LINK" 2>/dev/null || true)" = "$DEST/$FETCH" ]; then
        echo "OK: $FETCH_LINK already points at $DEST/$FETCH."
    else
        echo "WARNING: $FETCH_LINK exists and is not ours - left alone. Call the" >&2
        echo "         wrapper as $DEST/$FETCH, or put $DEST on PATH." >&2
    fi
elif [ -d "$(dirname "$FETCH_LINK")" ]; then
    $SUDO ln -s "$DEST/$FETCH" "$FETCH_LINK"
    FETCH_LINKED=1
fi

python3 -c 'import gssapi' 2>/dev/null || \
    echo "WARNING: python3-gssapi not found - is this machine ipa-client-enrolled?" >&2

REG='{"mcpServers":{"internal-tools":{"type":"stdio","command":"'"$DEST/$LAUNCH"'","args":["'"$MCP_URL"'"]}}}'

MANAGED_WROTE=0
ETC_EXISTED=0; [ -d /etc/claude-code ] && ETC_EXISTED=1
if [ "$MANAGED" = 1 ]; then
    if [ -f "$MANAGED_FILE" ] && grep -q '"internal-tools"' "$MANAGED_FILE"; then
        echo "OK: $MANAGED_FILE already registers internal-tools - left untouched."
    elif [ -f "$MANAGED_FILE" ]; then
        echo "WARNING: $MANAGED_FILE exists with other servers - merge manually:"; echo "$REG"
    else
        $SUDO mkdir -p /etc/claude-code
        printf '%s\n' "$REG" | $SUDO tee "$MANAGED_FILE" >/dev/null
        echo "Registered internal-tools machine-wide in $MANAGED_FILE."
        MANAGED_WROTE=1
    fi
else
    echo ""
    echo "Bridge installed to $DEST. Register it with:"
    echo "  claude mcp add internal-tools -- /usr/bin/python3 $DEST/$BRIDGE $MCP_URL"
    echo "or re-run with --managed to register it machine-wide in $MANAGED_FILE."
fi

# Record what this run changed, as the last step of a successful install. Every
# path below is script-literal, which is what makes building the JSON by
# concatenation safe. Non-fatal on failure, but loud: an install without a
# manifest still works today and cannot be cleanly uninstalled tomorrow.
FRAG_CREATED="\"$DEST/$BRIDGE\", \"$DEST/$REMOTE\", \"$DEST/$FETCH\", \"$DEST/$LAUNCH\""
[ "$FETCH_LINKED" = 1 ] && FRAG_CREATED="$FRAG_CREATED, \"$FETCH_LINK\""
[ "$MANAGED_WROTE" = 1 ] && FRAG_CREATED="$FRAG_CREATED, \"$MANAGED_FILE\""
FRAG_DIRS=""
[ "$DEST_EXISTED" = 0 ] && FRAG_DIRS="\"$DEST\""
if [ "$MANAGED_WROTE" = 1 ] && [ "$ETC_EXISTED" = 0 ]; then
    [ -n "$FRAG_DIRS" ] && FRAG_DIRS="$FRAG_DIRS, "
    FRAG_DIRS="$FRAG_DIRS\"/etc/claude-code\""
fi
MERGE_SUDO="$SUDO"
merge_manifest "$MANIFEST" '{
  "written_by": "install-bridge.sh",
  "created": ['"$FRAG_CREATED"'],
  "created_dirs": ['"$FRAG_DIRS"']
}' || echo "WARNING: could not update $MANIFEST - uninstall.sh will not know what this run changed." >&2
