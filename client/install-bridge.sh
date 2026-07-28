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
# What authenticates the bytes: TLS, and nothing else. On an enrolled host
# /etc/ipa/ca.crt is the realm CA, and the download below is pinned to it with
# curl --cacert, so only a certificate issued by the realm CA is accepted for
# the publisher. When the MCP host serves the bundle itself the pin still
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
            echo "The download is pinned to the realm CA (/etc/ipa/ca.crt) when that"
            echo "file is present, and warns loudly when it has to fall back to the"
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

# Pin the TLS leg to the realm CA, exactly as client/setup.sh does. This host is
# expected to be IPA-enrolled already, so /etc/ipa/ca.crt is the CA it trusts.
CURL_CA=""
CA_PIN_DROPPED=0
if [ -r /etc/ipa/ca.crt ]; then
    CURL_CA="--cacert /etc/ipa/ca.crt"
else
    echo "WARNING: /etc/ipa/ca.crt is not readable, so the realm CA pin is NOT in" >&2
    echo "         force for the download below. It falls back to the system trust" >&2
    echo "         store, where any publicly trusted CA can vouch for the publisher." >&2
    echo "         Is this machine ipa-client-enrolled?" >&2
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

fetch_retry "$BRIDGE" "$tmp/$BRIDGE" || {
    echo "ERROR: could not fetch $BASE/$BRIDGE - nothing was installed." >&2
    echo "  If this ran as part of enrolment, the IPA join may have SUCCEEDED while" >&2
    echo "  the MCP client shim was NOT installed. Finish by hand once the" >&2
    echo "  publisher is reachable:" >&2
    echo "    sh $0 --base-url $BASE --mcp-url $MCP_URL" >&2
    exit 1; }

# Install atomically: `install` writes via a temp file and renames, so a
# concurrent exec never sees a half-written bridge, and re-running just replaces
# it.
$SUDO mkdir -p "$DEST"
$SUDO install -m 0755 "$tmp/$BRIDGE" "$DEST/$BRIDGE"
python3 -c 'import gssapi' 2>/dev/null || \
    echo "WARNING: python3-gssapi not found - is this machine ipa-client-enrolled?" >&2

REG='{"mcpServers":{"internal-tools":{"type":"stdio","command":"/usr/bin/python3","args":["'"$DEST/$BRIDGE"'","'"$MCP_URL"'"]}}}'

if [ "$MANAGED" = 1 ]; then
    if [ -f "$MANAGED_FILE" ] && grep -q '"internal-tools"' "$MANAGED_FILE"; then
        echo "OK: $MANAGED_FILE already registers internal-tools - left untouched."
    elif [ -f "$MANAGED_FILE" ]; then
        echo "WARNING: $MANAGED_FILE exists with other servers - merge manually:"; echo "$REG"
    else
        $SUDO mkdir -p /etc/claude-code
        printf '%s\n' "$REG" | $SUDO tee "$MANAGED_FILE" >/dev/null
        echo "Registered internal-tools machine-wide in $MANAGED_FILE."
    fi
else
    echo ""
    echo "Bridge installed to $DEST. Register it with:"
    echo "  claude mcp add internal-tools -- /usr/bin/python3 $DEST/$BRIDGE $MCP_URL"
    echo "or re-run with --managed to register it machine-wide in $MANAGED_FILE."
fi
