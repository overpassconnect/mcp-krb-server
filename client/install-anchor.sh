#!/bin/sh
# install-anchor.sh - make this workstation the reverse-bridge anchor.
#
# Per-user and unprivileged, the mirror of install-bridge.sh: that one installs
# the bridge machine-wide as root, this one serves the three sockets a shared
# host forwards back (MCP, fetch, git) and adds the ssh RemoteForward that puts
# them there. Run as the
# person who will hold the ticket, never as root: a systemd --user service and a
# launchd LaunchAgent both belong to a login session, and the ticket the
# listeners read is that person's.
#
#   sh install-anchor.sh --mcp-url URL --domain D --ipa-url URL [--dry-run]
#                        [--windows-git]
#
# It is idempotent: re-running replaces the units and the ssh block in place.
# On every run, including the silent ones once the anchor is up, it also keeps
# the git identity of realm repositories equal to the ticket holder's IPA
# record (see sync_git_identity). --windows-git, which setup.ps1's wslkinit
# passes, does the same for the Windows git beside this WSL distro.
set -eu

MCP_URL=""; DOMAIN=""; IPA_URL=""; DRY=0; UNINSTALL=0; FORCE=0; WINGIT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --mcp-url)   MCP_URL="$2"; shift 2 ;;
        --domain)    DOMAIN="$2";  shift 2 ;;
        --ipa-url)   IPA_URL="$2"; shift 2 ;;
        --dry-run)   DRY=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        --force)     FORCE=1; shift ;;
        --windows-git) WINGIT=1; shift ;;
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

# The realm git identity: a file of this kit's own, and one includeIf in the
# global config that makes git read it inside a repository with a remote under
# https://*.DOMAIN/ and nowhere else. sync_git_identity below says why.
IDFILE="${XDG_CONFIG_HOME:-$HOME/.config}/mcp-krb/git-identity.gitconfig"

# A string as a POSIX extended regex that matches only itself.
ere_quote() { printf '%s\n' "$1" | sed 's/[][\.^$*+?(){}|]/\\&/g'; }

# The global includeIf keys, as git $1 spells them, whose path is $2. Found by
# value rather than by condition, so --uninstall needs no --domain. git.exe
# ends its lines with CR.
include_keys() {
    "$1" config --global --no-includes --get-regexp '^includeif\..*\.path$' 2>/dev/null \
        | tr -d '\r' | while read -r _k _v; do
            [ "$_v" = "$2" ] && printf '%s\n' "$_k"
        done | sort -u
}

# Remove git $1's global includeIf entries for path $2, and any section header
# that leaves empty: an empty header keeps its place, and a later --add would
# fill it there rather than at the end. Entries for other paths stay.
drop_include() {
    include_keys "$1" "$2" | while read -r _k; do
        "$1" config --global --unset-all "$_k" "^$(ere_quote "$2")\$" >/dev/null 2>&1 || :
        _sec="${_k%.path}"
        "$1" config --global --no-includes --get-regexp "^$(ere_quote "$_sec")\." >/dev/null 2>&1 \
            || "$1" config --global --remove-section "$_sec" >/dev/null 2>&1 || :
    done
}

# Make git $1's global includeIf for path $2 present, with no user.email or
# user.name after it. git keeps the last value it reads, so a [user] section
# below the include (git config --global user.email appends one when the file
# has none) would win inside realm repositories too; the entry is moved to the
# end when that happens. Returns 0 when it changed something, 1 when it was
# already in place; with --dry-run it only reports which.
ensure_include() {
    _want="includeif.hasconfig:remote.*.url:https://*.$DOMAIN/**.path=$2"
    _in_place="$("$1" config --global --no-includes --list 2>/dev/null | tr -d '\r' | awk -v w="$_want" '
        $0 == w { ok = 1; next }
        /^user\.(email|name)=/ { ok = 0 }
        END { print ok + 0 }')"
    [ "$_in_place" = 1 ] && return 1
    [ "$DRY" = 1 ] && return 0
    drop_include "$1" "$2"
    "$1" config --global --add "includeIf.hasconfig:remote.*.url:https://*.$DOMAIN/**.path" "$2"
}

# includeIf "hasconfig:remote.*.url:..." exists from git 2.36. An older git
# skips the condition as unknown, and says nothing.
reads_hasconfig() {
    _v="$("$1" version 2>/dev/null | tr -d '\r' | sed -n 's/^git version \([0-9]*\)\.\([0-9]*\).*/\1 \2/p')"
    set -- $_v
    [ "${1:-0}" -gt 2 ] || { [ "${1:-0}" -eq 2 ] && [ "${2:-0}" -ge 36 ]; }
}

# The Windows user's profile directory as C:/Users/name, asked of cmd.exe over
# WSL interop. Fails when interop is off or the answer is not a drive path.
win_home() {
    _h="$(cmd.exe /c echo %USERPROFILE% 2>/dev/null | tr -d '\r')"
    case "$_h" in
        [A-Za-z]:\\*) printf '%s\n' "$_h" | tr '\\' '/' ;;
        *) return 1 ;;
    esac
}

# Teardown is the exact inverse of what install writes, and needs none of the
# install arguments, so it runs before they are required.
if [ "$UNINSTALL" = 1 ]; then
    case "$(uname -s)" in
        Linux)
            systemctl --user disable --now mcp-krb-anchor-mcp.service \
                mcp-krb-anchor-fetch.service mcp-krb-anchor-git.service 2>/dev/null || true
            rm -f "$HOME/.config/systemd/user/mcp-krb-anchor-mcp.service" \
                  "$HOME/.config/systemd/user/mcp-krb-anchor-fetch.service" \
                  "$HOME/.config/systemd/user/mcp-krb-anchor-git.service"
            systemctl --user daemon-reload 2>/dev/null || true ;;
        Darwin)
            for _l in anchor-mcp anchor-fetch anchor-git; do
                launchctl bootout "gui/$(id -u)/com.overpassconnect.mcp-krb.$_l" 2>/dev/null || true
                rm -f "$HOME/Library/LaunchAgents/com.overpassconnect.mcp-krb.$_l.plist"
            done ;;
    esac
    strip_ssh_block
    rm -f "$HOME/.mcp-krb.sock" "$HOME/.mcp-krb-fetch.sock" "$HOME/.mcp-krb-git.sock"
    if command -v git >/dev/null 2>&1; then
        drop_include git "$IDFILE"
    fi
    rm -f "$IDFILE"; rmdir "$(dirname "$IDFILE")" 2>/dev/null || :
    if [ "$WINGIT" = 1 ] && command -v git.exe >/dev/null 2>&1 && _wh="$(win_home)"; then
        drop_include git.exe "$_wh/.config/mcp-krb/git-identity.gitconfig"
        _wf="$(wslpath -u "$_wh/.config/mcp-krb/git-identity.gitconfig" 2>/dev/null || :)"
        if [ -n "$_wf" ]; then rm -f "$_wf"; rmdir "$(dirname "$_wf")" 2>/dev/null || :; fi
    fi
    # An earlier version set the global user.email itself and kept the address
    # it replaced under mcp-krb.priorUserEmail. Put that back if it is there.
    if command -v git >/dev/null 2>&1 \
            && git config --global --get mcp-krb.priorUserEmail >/dev/null 2>&1; then
        _prior="$(git config --global --get mcp-krb.priorUserEmail)"
        if [ -n "$_prior" ]; then git config --global user.email "$_prior"
        else git config --global --unset user.email || :; fi
        git config --global --unset mcp-krb.priorUserEmail || :
        echo "anchor: git user.email restored to ${_prior:-unset}."
    fi
    echo "anchor: removed units/agents, the ssh block, the sockets and the realm git identity."
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

# Who holds the ticket. MIT klist labels it "Default principal:", Heimdal (macOS)
# says "Principal:", so match the first user@realm in the output rather than a
# label, and cut at @.
princ="$(klist 2>/dev/null | grep -oE '[[:alnum:]._-]+@[[:alnum:].-]+' | head -1 | cut -d@ -f1)"

# The realm CA that pins the IPA lookup below. Linux enrolment leaves it at the
# first path; setup-macos.sh saves it to the second, because a Mac has no
# /etc/ipa and its curl may be Homebrew's, which ignores the System keychain the
# CA was added to. An explicit --cacert on a file works whichever curl is first
# on PATH; without it the lookup fails only on the Homebrew-curl Macs, which is
# the intermittent "could not read a numeric uid" nobody could reproduce.
# Kept as a bare path and expanded quoted: the macOS APPDIR has a space in it
# ("Application Support"), so an unquoted "--cacert $path" splits into a bogus
# CA file plus a stray URL and the login fails with a misleading "kinit" hint.
CA=""
for _ca in /etc/ipa/ca.crt "$APPDIR/realm-ca.crt"; do
    [ -r "$_ca" ] && { CA="$_ca"; break; }
done

# This person's IPA record: one Kerberos login and one user_show, on every run.
# Two readers use it: the git identity just below, refreshed on every ticket,
# and the uid further down, needed only while the anchor is being set up. Every
# kinit waits on these two, so both are bounded: a slow IPA costs seconds.
CJ="$(mktemp)"; IJ="$(mktemp)"; trap 'rm -f "$CJ" "$IJ"' EXIT
code=000
if [ -n "$princ" ]; then
    code="$(curl -sS --connect-timeout 5 --max-time 20 -o /dev/null -w '%{http_code}' \
        ${CA:+--cacert "$CA"} --negotiate -u : -c "$CJ" \
        -H "Referer: $IPA_URL/ipa" "$IPA_URL/ipa/session/login_kerberos" 2>/dev/null || echo 000)"
    if [ "$code" = 200 ]; then
        curl -sS --connect-timeout 5 --max-time 20 \
            ${CA:+--cacert "$CA"} --negotiate -u : -b "$CJ" -H "Referer: $IPA_URL/ipa" \
            -H 'Content-Type: application/json' -H 'Accept: application/json' \
            -d '{"method":"user_show","params":[["'"$princ"'"],{"version":"2.251"}],"id":0}' \
            "$IPA_URL/ipa/session/json" > "$IJ" 2>/dev/null || :
    fi
fi

# The git identity follows IPA, inside realm repositories only. A commit
# carries whatever name and address git is configured with, the forges credit
# it by that address, and a push through Gitea and its mirror changes nothing
# in it. So the name and address IPA has for this person are written to
# $IDFILE, and one includeIf in the global config makes git read that file in a
# repository with a remote under https://*.DOMAIN/. The global user.email and
# user.name, which every other repository uses, are not touched: a personal
# address for GitHub stays personal. A repository's own user.email (git config
# without --global) still wins inside it.
#
# Silent unless it changes something, and never fatal: a ticket must not fail
# because IPA was slow to answer, and the kinit wrappers return this script's
# status.
sync_git_identity() {
    command -v git >/dev/null 2>&1 || return 0
    [ -s "$IJ" ] || return 0
    _id="$("$PY" -c '
import json, sys
r = json.load(sys.stdin)["result"]["result"]
first = lambda k: (r.get(k) or [""])[0]
print(first("mail"))
print(" ".join(x for x in (first("givenname"), first("sn")) if x))
' < "$IJ" 2>/dev/null)" || return 0
    _mail="$(printf '%s\n' "$_id" | sed -n 1p)"
    _name="$(printf '%s\n' "$_id" | sed -n 2p)"
    case "$_mail" in *@*.*) ;; *) return 0 ;; esac
    _who="${_name:+$_name }<$_mail>"

    # An earlier version of this step set the global user.email itself and kept
    # the address it replaced under mcp-krb.priorUserEmail. Undo that, unless
    # the global address has been changed by hand since.
    if git config --global --get mcp-krb.priorUserEmail >/dev/null 2>&1; then
        _prior="$(git config --global --get mcp-krb.priorUserEmail || :)"
        if [ "$DRY" = 1 ]; then
            echo "would: put the global git user.email back to ${_prior:-unset}"
        else
            if [ "$(git config --global user.email 2>/dev/null || :)" = "$_mail" ]; then
                if [ -n "$_prior" ]; then git config --global user.email "$_prior" || :
                else git config --global --unset user.email || :; fi
                echo "git: global user.email put back to ${_prior:-unset}; $_mail is for realm repositories only now."
            fi
            git config --global --unset mcp-krb.priorUserEmail || :
        fi
    fi

    _changed=0
    if [ "$(git config -f "$IDFILE" user.email 2>/dev/null || :)" != "$_mail" ] \
            || [ "$(git config -f "$IDFILE" user.name 2>/dev/null || :)" != "$_name" ]; then
        _changed=1
        if [ "$DRY" = 1 ]; then
            echo "would: write $_who to $IDFILE"
        else
            mkdir -p "$(dirname "$IDFILE")" || return 0
            {   echo "# Written by mcp-krb install-anchor.sh from your IPA record on every kinit."
                echo "# git reads it only in repositories with a remote under https://*.$DOMAIN/."
            } > "$IDFILE.tmp" || return 0
            git config -f "$IDFILE.tmp" user.email "$_mail" || return 0
            if [ -n "$_name" ]; then git config -f "$IDFILE.tmp" user.name "$_name" || return 0; fi
            mv -f "$IDFILE.tmp" "$IDFILE" || return 0
        fi
    fi
    if ensure_include git "$IDFILE"; then
        _changed=1
        if [ "$DRY" = 1 ]; then
            echo "would: add an includeIf for https://*.$DOMAIN/ at the end of the global git config"
        fi
    fi
    if [ "$_changed" = 1 ] && [ "$DRY" != 1 ]; then
        echo "git: repositories under https://*.$DOMAIN/ commit as $_who, as IPA has it for $princ."
        reads_hasconfig git || echo "git: WARNING: $(git version) predates includeIf hasconfig (2.36) and ignores it. Upgrade git, or set user.email in each realm repository." >&2
    fi
    if [ "$WINGIT" = 1 ]; then sync_windows_git "$_changed" "$_who"; fi
    return 0
}

# The Windows git beside this distro reads its own global config, and a checkout
# on the Windows filesystem gets commits from either git. So with --windows-git
# the same file is copied into the Windows profile and git.exe, over WSL
# interop, is given the same includeIf. $1 is 1 when the identity changed in
# this run: a Windows side that cannot be reached is reported then, not on
# every kinit.
sync_windows_git() {
    command -v git.exe >/dev/null 2>&1 || return 0
    if ! _wh="$(win_home)" \
            || ! _wf="$(wslpath -u "$_wh/.config/mcp-krb/git-identity.gitconfig" 2>/dev/null)"; then
        if [ "$1" = 1 ]; then
            echo "git (Windows): WARNING: Windows is not reachable over WSL interop, so Windows git keeps its own identity." >&2
        fi
        return 0
    fi
    _wi="$_wh/.config/mcp-krb/git-identity.gitconfig"
    _wchanged=0
    if ! cmp -s "$IDFILE" "$_wf"; then
        _wchanged=1
        if [ "$DRY" = 1 ]; then
            echo "would: copy $IDFILE to $_wi for Windows git"
        else
            mkdir -p "$(dirname "$_wf")" && cp -f "$IDFILE" "$_wf" || return 0
        fi
    fi
    if ensure_include git.exe "$_wi"; then
        _wchanged=1
        if [ "$DRY" = 1 ]; then
            echo "would: add an includeIf for https://*.$DOMAIN/ at the end of Windows git's global config"
        fi
    fi
    if [ "$_wchanged" = 1 ] && [ "$DRY" != 1 ]; then
        echo "git (Windows): repositories under https://*.$DOMAIN/ commit as $2."
        reads_hasconfig git.exe || echo "git (Windows): WARNING: $(git.exe version | tr -d '\r') predates includeIf hasconfig (2.36) and ignores it. Upgrade Git for Windows." >&2
    fi
    return 0
}
sync_git_identity

# Already configured? A kinit wrapper calls this on every ticket, so a re-run
# must be a silent no-op: units up and the ssh block present means nothing to do
# and nothing to say. All three listeners are checked, so an anchor set up
# before one of them existed is completed on the next kinit rather than left a
# socket short. --force reconfigures anyway.
if [ "$FORCE" != 1 ]; then
    _up=0
    if grep -q "^$BEGIN\$" "$HOME/.ssh/config" 2>/dev/null; then
        _up=1
        case "$(uname -s)" in
            Linux)
                for _u in mcp fetch git; do
                    systemctl --user is-active "mcp-krb-anchor-$_u.service" >/dev/null 2>&1 || _up=0
                done ;;
            Darwin)
                _loaded="$(launchctl list 2>/dev/null)"
                for _u in mcp fetch git; do
                    printf '%s\n' "$_loaded" | grep -q "com\.overpassconnect\.mcp-krb\.anchor-$_u" || _up=0
                done ;;
            *) _up=0 ;;
        esac
    fi
    [ "$_up" = 1 ] && exit 0
fi

# The VM-side uid. The same IPA uid on every enrolled host, but NOT this
# workstation's local uid when the workstation is not itself enrolled (a plain
# WSL box holds a ticket without an SSSD identity). So it comes from the IPA
# record read above, and a missing ticket or a failed login is a hard stop here,
# not a guess.
[ -n "$princ" ] || { echo "install-anchor.sh: no Kerberos ticket. Run kinit, then" >&2
    echo "  re-run: the VM-side uid is read from IPA and cannot be guessed." >&2; exit 2; }
[ "$code" = 200 ] || { echo "install-anchor.sh: IPA login failed ($code) at $IPA_URL." >&2
    echo "  A valid ticket is needed to read your uid. kinit and retry." >&2; exit 2; }
uid="$("$PY" -c 'import json,sys; print(json.load(sys.stdin)["result"]["result"]["uidnumber"][0])' \
    < "$IJ" 2>/dev/null || true)"
case "$uid" in
    ''|*[!0-9]*) echo "install-anchor.sh: could not read a numeric uid for $princ from IPA." >&2; exit 2 ;;
esac
echo "anchor: $princ has IPA uid $uid; serving on this workstation."

# Workstation-side sockets. Deliberately NOT /run/user/<uid>/mcp-krb*.sock: those
# are the paths the launcher, krb-fetch and krb-git check to decide
# remote-vs-local, so the anchor must serve elsewhere or this machine would
# route to itself.
LSOCK="$HOME/.mcp-krb.sock"
LFSOCK="$HOME/.mcp-krb-fetch.sock"
LGSOCK="$HOME/.mcp-krb-git.sock"
# The shared-host end, where ssh -R lands them and the launcher looks.
RSOCK="/run/user/$uid/mcp-krb.sock"
RFSOCK="/run/user/$uid/mcp-krb-fetch.sock"
RGSOCK="/run/user/$uid/mcp-krb-git.sock"

install_systemd() {
    UD="$HOME/.config/systemd/user"
    if [ "$DRY" = 1 ]; then
        echo "would: write $UD/mcp-krb-anchor-{mcp,fetch,git}.service and enable --now all three"
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
    cat > "$UD/mcp-krb-anchor-git.service" <<UNIT
[Unit]
Description=mcp-krb anchor: serve the git socket for hosts that forward it back
Documentation=https://github.com/overpassconnect/mcp-krb-server
After=default.target

[Service]
Type=simple
ExecStart=$PY $APPDIR/mcp-krb-bridge.py --git-listen %h/.mcp-krb-git.sock
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
UNIT
    systemctl --user daemon-reload
    systemctl --user enable --now mcp-krb-anchor-mcp.service \
        mcp-krb-anchor-fetch.service mcp-krb-anchor-git.service
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
    gitp="$LA/com.overpassconnect.mcp-krb.anchor-git.plist"
    if [ "$DRY" = 1 ]; then
        echo "would: write $mcp, $fetch and $gitp and launchctl bootstrap all three"
        return 0
    fi
    mkdir -p "$LA"
    write_plist "com.overpassconnect.mcp-krb.anchor-mcp" "$mcp" \
        "$PY" "$APPDIR/mcp-krb-bridge.py" --listen "$LSOCK" "$MCP_URL"
    write_plist "com.overpassconnect.mcp-krb.anchor-fetch" "$fetch" \
        "$PY" "$APPDIR/mcp-krb-bridge.py" --fetch-listen "$LFSOCK"
    write_plist "com.overpassconnect.mcp-krb.anchor-git" "$gitp" \
        "$PY" "$APPDIR/mcp-krb-bridge.py" --git-listen "$LGSOCK"
    for _f in "$mcp" "$fetch" "$gitp"; do
        _svc="gui/$(id -u)/$(basename "$_f" .plist)"
        launchctl bootout "$_svc" 2>/dev/null || true
        # bootout returns before a running job has left the domain, and a
        # bootstrap over it fails with "5: Input/output error". Wait it out.
        _n=0
        while launchctl print "$_svc" >/dev/null 2>&1 && [ "$_n" -lt 50 ]; do
            sleep 0.1; _n=$((_n + 1))
        done
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
    printf '    RemoteForward %s %s\n' "$RGSOCK" "$LGSOCK"
    printf '%s\n' "$END"
} >> "$SSHCFG"
chmod 600 "$SSHCFG"
echo "anchor: ssh RemoteForward added for *.$DOMAIN (uid $uid)."
echo "anchor: done. A shared host you ssh to now gets the sockets; infra hosts"
echo "        get only an unused socket, and none of it outlives the ssh session."
