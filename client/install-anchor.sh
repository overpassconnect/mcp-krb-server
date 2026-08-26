#!/bin/sh
# install-anchor.sh - make this workstation the reverse-bridge anchor.
#
# Per-user and unprivileged, the mirror of install-bridge.sh: that one installs
# the bridge machine-wide as root, this one serves the two sockets a shared host
# forwards back and adds the ssh RemoteForward that puts them there. Run as the
# person who will hold the ticket, never as root: a systemd --user service and a
# launchd LaunchAgent both belong to a login session, and the ticket the
# listeners read is that person's.
#
#   sh install-anchor.sh --mcp-url URL --domain D --ipa-url URL [--dry-run]
#
# It is idempotent: re-running replaces the units and the ssh block in place.
set -eu

MCP_URL=""; DOMAIN=""; IPA_URL=""; DRY=0; UNINSTALL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --mcp-url)   MCP_URL="$2"; shift 2 ;;
        --domain)    DOMAIN="$2";  shift 2 ;;
        --ipa-url)   IPA_URL="$2"; shift 2 ;;
        --dry-run)   DRY=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        *) echo "install-anchor.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

# The ssh block markers, needed by both install and uninstall.
BEGIN="# BEGIN mcp-krb-anchor"
END="# END mcp-krb-anchor"

strip_ssh_block() {
    # Remove any existing mcp-krb-anchor block from ~/.ssh/config in place.
    _cfg="$HOME/.ssh/config"
    [ -f "$_cfg" ] || return 0
    _t="$(mktemp)"
    awk -v b="$BEGIN" -v e="$END" '
        $0==b {skip=1} skip && $0==e {skip=0; next} !skip {print}' "$_cfg" > "$_t"
    cat "$_t" > "$_cfg"; rm -f "$_t"; chmod 600 "$_cfg"
}

# Teardown is the exact inverse of what install writes, and needs none of the
# install arguments, so it runs before they are required.
if [ "$UNINSTALL" = 1 ]; then
    case "$(uname -s)" in
        Linux)
            systemctl --user disable --now \
                mcp-krb-anchor-mcp.service mcp-krb-anchor-fetch.service 2>/dev/null || true
            rm -f "$HOME/.config/systemd/user/mcp-krb-anchor-mcp.service" \
                  "$HOME/.config/systemd/user/mcp-krb-anchor-fetch.service"
            systemctl --user daemon-reload 2>/dev/null || true ;;
        Darwin)
            for _l in anchor-mcp anchor-fetch; do
                launchctl bootout "gui/$(id -u)/com.overpassconnect.mcp-krb.$_l" 2>/dev/null || true
                rm -f "$HOME/Library/LaunchAgents/com.overpassconnect.mcp-krb.$_l.plist"
            done ;;
    esac
    strip_ssh_block
    rm -f "$HOME/.mcp-krb.sock" "$HOME/.mcp-krb-fetch.sock"
    echo "anchor: removed units/agents, the ssh block, and the sockets."
    exit 0
fi

[ -n "$MCP_URL" ] || { echo "install-anchor.sh: --mcp-url is required" >&2; exit 2; }
[ -n "$DOMAIN"  ] || { echo "install-anchor.sh: --domain is required"  >&2; exit 2; }
[ -n "$IPA_URL" ] || { echo "install-anchor.sh: --ipa-url is required" >&2; exit 2; }

if [ "$(id -u)" = 0 ]; then
    echo "install-anchor.sh: refusing to run as root. The anchor is a per-user" >&2
    echo "  service that reads your ticket; run it as yourself." >&2
    exit 2
fi

# The bridge this serves with. Same resolution the launcher uses, so all three
# agree on where the kit lives.
APPDIR=""
for _d in /opt/mcp-krb "$HOME/Library/Application Support/mcp-krb"; do
    [ -f "$_d/mcp-krb-bridge.py" ] && { APPDIR="$_d"; break; }
done
[ -n "$APPDIR" ] || { echo "install-anchor.sh: no bridge at /opt/mcp-krb or the macOS path." >&2
    echo "  Install the bridge first (install-bridge.sh / setup)." >&2; exit 2; }
if [ -x "$APPDIR/venv/bin/python3" ]; then PY="$APPDIR/venv/bin/python3"; else PY=python3; fi

# The VM-side uid. The same IPA uid on every enrolled host, but NOT this
# workstation's local uid when the workstation is not itself enrolled (a plain
# WSL box holds a ticket without an SSSD identity). So it is read from IPA with
# the ticket we hold now, and a missing ticket is a hard stop, not a guess.
princ="$(klist 2>/dev/null | sed -n 's/^Default principal: \([^@]*\)@.*/\1/p' | head -1)"
[ -n "$princ" ] || { echo "install-anchor.sh: no Kerberos ticket. Run kinit, then" >&2
    echo "  re-run: the VM-side uid is read from IPA and cannot be guessed." >&2; exit 2; }

CA=""
[ -r /etc/ipa/ca.crt ] && CA="--cacert /etc/ipa/ca.crt"
CJ="$(mktemp)"; trap 'rm -f "$CJ"' EXIT
# shellcheck disable=SC2086
code="$(curl -sS -o /dev/null -w '%{http_code}' $CA --negotiate -u : -c "$CJ" \
    -H "Referer: $IPA_URL/ipa" "$IPA_URL/ipa/session/login_kerberos" 2>/dev/null || echo 000)"
[ "$code" = 200 ] || { echo "install-anchor.sh: IPA login failed ($code) at $IPA_URL." >&2
    echo "  A valid ticket is needed to read your uid. kinit and retry." >&2; exit 2; }
# shellcheck disable=SC2086
uid="$(curl -sS $CA --negotiate -u : -b "$CJ" -H "Referer: $IPA_URL/ipa" \
    -H 'Content-Type: application/json' -H 'Accept: application/json' \
    -d '{"method":"user_show","params":[["'"$princ"'"],{"version":"2.251"}],"id":0}' \
    "$IPA_URL/ipa/session/json" 2>/dev/null \
    | $PY -c 'import json,sys; print(json.load(sys.stdin)["result"]["result"]["uidnumber"][0])' 2>/dev/null || true)"
case "$uid" in
    ''|*[!0-9]*) echo "install-anchor.sh: could not read a numeric uid for $princ from IPA." >&2; exit 2 ;;
esac
echo "anchor: $princ has IPA uid $uid; serving on this workstation."

# Workstation-side sockets. Deliberately NOT /run/user/<uid>/mcp-krb.sock: that
# is the path the launcher and mcp-fetch check to decide remote-vs-local, so the
# anchor must serve elsewhere or this machine would route to itself.
LSOCK="$HOME/.mcp-krb.sock"
LFSOCK="$HOME/.mcp-krb-fetch.sock"
# The shared-host end, where ssh -R lands them and the launcher looks.
RSOCK="/run/user/$uid/mcp-krb.sock"
RFSOCK="/run/user/$uid/mcp-krb-fetch.sock"

install_systemd() {
    UD="$HOME/.config/systemd/user"
    if [ "$DRY" = 1 ]; then
        echo "would: write $UD/mcp-krb-anchor-{mcp,fetch}.service and enable --now both"
        return 0
    fi
    mkdir -p "$UD"
    cat > "$UD/mcp-krb-anchor-mcp.service" <<UNIT
[Unit]
Description=mcp-krb anchor: serve the MCP socket for hosts that forward it back
Documentation=https://github.com/overpassconnect/mcp-krb-server
After=default.target

[Service]
Type=simple
ExecStart=$PY $APPDIR/mcp-krb-bridge.py --listen %h/.mcp-krb.sock $MCP_URL
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
UNIT
    cat > "$UD/mcp-krb-anchor-fetch.service" <<UNIT
[Unit]
Description=mcp-krb anchor: serve the fetch socket for hosts that forward it back
Documentation=https://github.com/overpassconnect/mcp-krb-server
After=default.target

[Service]
Type=simple
ExecStart=$PY $APPDIR/mcp-krb-bridge.py --fetch-listen %h/.mcp-krb-fetch.sock
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
UNIT
    systemctl --user daemon-reload
    systemctl --user enable --now mcp-krb-anchor-mcp.service mcp-krb-anchor-fetch.service
    echo "anchor: systemd --user units enabled and started."
}

write_plist() {
    # $1 label  $2 outfile  $3.. ExecStart argv
    _label="$1"; _out="$2"; shift 2
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        echo '<plist version="1.0"><dict>'
        echo "  <key>Label</key><string>$_label</string>"
        echo '  <key>ProgramArguments</key><array>'
        for _a in "$@"; do printf '    <string>%s</string>\n' "$_a"; done
        echo '  </array>'
        echo '  <key>RunAtLoad</key><true/>'
        echo '  <key>KeepAlive</key><true/>'
        echo '</dict></plist>'
    } > "$_out"
}

install_launchd() {
    LA="$HOME/Library/LaunchAgents"
    mcp="$LA/com.overpassconnect.mcp-krb.anchor-mcp.plist"
    fetch="$LA/com.overpassconnect.mcp-krb.anchor-fetch.plist"
    if [ "$DRY" = 1 ]; then
        echo "would: write $mcp and $fetch and launchctl bootstrap both"
        return 0
    fi
    mkdir -p "$LA"
    write_plist "com.overpassconnect.mcp-krb.anchor-mcp" "$mcp" \
        "$PY" "$APPDIR/mcp-krb-bridge.py" --listen "$LSOCK" "$MCP_URL"
    write_plist "com.overpassconnect.mcp-krb.anchor-fetch" "$fetch" \
        "$PY" "$APPDIR/mcp-krb-bridge.py" --fetch-listen "$LFSOCK"
    for _f in "$mcp" "$fetch"; do
        launchctl bootout "gui/$(id -u)/$(basename "$_f" .plist)" 2>/dev/null || true
        launchctl bootstrap "gui/$(id -u)" "$_f"
    done
    echo "anchor: launchd agents loaded."
}

case "$(uname -s)" in
    Linux)  install_systemd ;;
    Darwin) install_launchd ;;
    *) echo "install-anchor.sh: unsupported OS $(uname -s)" >&2; exit 2 ;;
esac

# The ssh RemoteForward, in this script's own managed block so its markers do
# not collide with the GSSAPI block the OS installers write. Two Host *.DOMAIN
# blocks are fine; ssh accumulates their options.
SSHCFG="$HOME/.ssh/config"
if [ "$DRY" = 1 ]; then
    echo "would: add a $BEGIN block to $SSHCFG forwarding to *.$DOMAIN (uid $uid)"
    exit 0
fi
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
touch "$SSHCFG"; chmod 600 "$SSHCFG"
strip_ssh_block                       # drop a previous block, then re-add
{
    printf '%s\n' "$BEGIN"
    printf 'Host *.%s\n' "$DOMAIN"
    printf '    RemoteForward %s %s\n' "$RSOCK"  "$LSOCK"
    printf '    RemoteForward %s %s\n' "$RFSOCK" "$LFSOCK"
    printf '%s\n' "$END"
} >> "$SSHCFG"
chmod 600 "$SSHCFG"
echo "anchor: ssh RemoteForward added for *.$DOMAIN (uid $uid)."
echo "anchor: done. A shared host you ssh to now gets the sockets; infra hosts"
echo "        get only an unused socket, and none of it outlives the ssh session."
