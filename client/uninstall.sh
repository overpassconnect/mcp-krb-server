#!/bin/sh
# uninstall.sh - reverse what the client installers recorded in the install
# manifest. Runs on an IPA-enrolled Linux workstation, and inside WSL when
# invoked by uninstall.ps1.
#
#   sh uninstall.sh              # default: DRY RUN - print the plan, change nothing
#   sh uninstall.sh --yes        # apply the plan
#
#   --keep-packages   leave apt/dnf packages alone even if this kit installed them
#   --managed         also remove the machine-wide /etc/claude-code registration.
#                     Deliberately opt-in, mirroring install-bridge.sh --managed:
#                     that file serves every user on the machine, so removing it
#                     is a fleet decision, not a per-user one.
#
# Everything removed or restored here is justified by an entry in
# an install-manifest.json saying the installer created or replaced
# it. No manifest means no guessing: the script prints what a manifest would
# have told it and exits non-zero, because an uninstaller that improvises
# either leaves things behind or deletes things it did not install.
#
# What this script deliberately does not do:
#   - un-enrol from FreeIPA. That is a realm-side, irreversible-from-here
#     change with its own command, printed at the end. A test asserts no code
#     path in this file ever calls it.
#   - remove packages the manifest records as already present: the machine had
#     them before this kit arrived.
set -eu

# --root is a test hook: treat DIR as the filesystem root, so the test suite
# can drive the whole script against a synthetic tree. Under --root nothing
# that touches host state (packages, trust store, tickets) is executed, only
# printed, and sudo is never used, because the tree belongs to the test.
ROOT=""
YES=0
KEEP_PACKAGES=0
MANAGED=0

usage() {
    echo "usage: sh uninstall.sh [--yes] [--dry-run] [--keep-packages] [--managed]"
    echo ""
    echo "  Default is a dry run: print the plan and change nothing."
    echo "  --yes            apply the plan"
    echo "  --keep-packages  never remove packages, even kit-installed ones"
    echo "  --managed        also remove the machine-wide MCP registration in"
    echo "                   /etc/claude-code (affects every user on this machine)"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --yes) YES=1 ;;
        --dry-run) YES=0 ;;
        --keep-packages) KEEP_PACKAGES=1 ;;
        --managed) MANAGED=1 ;;
        --root)
            [ $# -ge 2 ] || { echo "ERROR: --root needs a directory" >&2; exit 2; }
            ROOT="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

SUDO=""
if [ -z "$ROOT" ] && [ "$(id -u)" != "0" ]; then SUDO="sudo"; fi

say() { printf '%s\n' "$*"; }

# Where the installers put things differs by platform. A Mac has no /opt
# convention and setup-macos.sh needs no sudo for the bridge, so its tree
# lives under the user's Library; the machine-wide MCP policy has its own
# macOS location too.
if [ "$(uname -s)" = Darwin ]; then
    APPROOT="$HOME/Library/Application Support/mcp-krb"
    MANAGED_FILE="/Library/Application Support/ClaudeCode/managed-mcp.json"
else
    APPROOT="/opt/mcp-krb"
    MANAGED_FILE="/etc/claude-code/managed-mcp.json"
fi

MANIFEST="$ROOT$APPROOT/install-manifest.json"

if [ ! -f "$MANIFEST" ]; then
    say "ERROR: no install manifest at $MANIFEST - refusing to guess."
    say ""
    say "The manifest is what records which of the following this kit actually"
    say "created on THIS machine, as opposed to what was already here:"
    say "  $APPROOT   (bridge, backups, manifest)"
    say "  $MANAGED_FILE   (only if --managed was used)"
    if [ "$(uname -s)" = Darwin ]; then
        say "  /etc/resolver/<domain>                      (split DNS)"
        say "  /etc/krb5.conf                              (replaced with backup)"
        say "  the realm CA in /Library/Keychains/System.keychain"
        say "  the Host block in ~/.ssh/config"
    else
        say "  /usr/local/share/ca-certificates/realm-ca.crt   (WSL only)"
        say "  /etc/krb5.conf                              (WSL only, replaced with backup)"
        say "  krb5-user, python3-gssapi                   (WSL only, if apt installed them)"
    fi
    say ""
    say "Without it, removing any of these may delete something the machine had"
    say "before this kit arrived. Review the list and remove by hand what you"
    say "know this kit created; an install run new enough to write a manifest"
    say "records all of it."
    exit 1
fi

# Parse once, up front, with the same tool the installers wrote it with. A
# manifest that does not parse aborts the whole run before anything is removed.
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
python3 - "$MANIFEST" "$tmp" <<'PY' || { echo "ERROR: cannot read $MANIFEST - nothing was removed." >&2; exit 1; }
import json, os, sys

path, out = sys.argv[1], sys.argv[2]
try:
    with open(path) as f:
        doc = json.load(f)
except ValueError as exc:
    sys.stderr.write('uninstall: %s is not valid JSON: %s\n' % (path, exc))
    sys.exit(1)
if doc.get('manifest_version') != 1:
    sys.stderr.write('uninstall: unknown manifest_version %r\n'
                     % (doc.get('manifest_version'),))
    sys.exit(1)

def dump(name, lines):
    # newline='' so a Windows python (the Git Bash test environment) does not
    # write \r\n and hand every sh read-loop a path with a trailing CR.
    with open(os.path.join(out, name), 'w', newline='') as f:
        for line in lines:
            f.write(line + '\n')

dump('created', doc.get('created', []))
dump('created_dirs', doc.get('created_dirs', []))
dump('packages', doc.get('packages_installed', []))
dump('replaced', ['%s\t%s' % (k, v) for k, v in doc.get('replaced', {}).items()])
# Not a path: removing it is a keychain operation, so it gets its own step.
dump('cert_sha1', [doc['trusted_cert_sha1']] if doc.get('trusted_cert_sha1') else [])
PY

# A manifest is data, not authority: only paths this kit is known to own may be
# acted on, so a corrupted manifest cannot direct a root uninstall at an
# arbitrary file.
path_is_ours() {
    case "$1" in
        "$APPROOT"|"$APPROOT"/*) return 0 ;;
        /etc/claude-code|/etc/claude-code/*) return 0 ;;
        "$MANAGED_FILE") return 0 ;;
        # The mcp-fetch symlink, and only when the installer recorded creating
        # it: an mcp-fetch that was already there is somebody else's.
        /usr/local/bin/mcp-fetch) return 0 ;;
        # Firefox-in-WSL: the Mozilla repo, its pin and keyring, and the policy
        # file. Each is only ever removed when the manifest says this kit created
        # it, so a machine that already had the repo keeps it.
        /etc/apt/sources.list.d/mozilla.list) return 0 ;;
        /etc/apt/preferences.d/mozilla) return 0 ;;
        /etc/apt/keyrings/packages.mozilla.org.asc) return 0 ;;
        /etc/firefox/policies|/etc/firefox/policies/*) return 0 ;;
        # The sshd drop-in setup.sh writes on a shared host so the reverse
        # bridge's forwarded socket rebinds. Removed only when the manifest
        # records this kit created it.
        /etc/ssh/sshd_config.d/50-mcp-krb-streamlocal.conf) return 0 ;;
        /etc/krb5.conf) return 0 ;;
        /etc/resolver/*) return 0 ;;
        /usr/local/share/ca-certificates/*) return 0 ;;
        *) return 1 ;;
    esac
}

if [ "$YES" = 1 ]; then say "Uninstalling per $MANIFEST:"; else say "DRY RUN - the plan per $MANIFEST (pass --yes to apply):"; fi

# 1. The MCP registration comes out first, so no session can launch a bridge
#    this run is about to delete.
CREATED_MANAGED=0
grep -qx "$MANAGED_FILE" "$tmp/created" && CREATED_MANAGED=1
if [ -f "$ROOT$MANAGED_FILE" ]; then
    if [ "$CREATED_MANAGED" = 1 ] && [ "$MANAGED" = 1 ]; then
        say "  remove machine-wide registration $MANAGED_FILE"
        if [ "$YES" = 1 ]; then $SUDO rm -f "$ROOT$MANAGED_FILE"; fi
    elif [ "$CREATED_MANAGED" = 1 ]; then
        say "  left alone: $MANAGED_FILE (machine-wide; pass --managed to remove it)"
    else
        say "  left alone: $MANAGED_FILE was not created by this kit - remove the"
        say "  internal-tools entry from it by hand if you added one."
    fi
fi
say "  note: a per-user registration made with 'claude mcp add' is yours, not"
say "  the installer's: remove it with 'claude mcp remove internal-tools'."

# 1b. The reverse-bridge anchor is per-user: its systemd --user service and its
#     ssh RemoteForward block belong to the person who ran install-anchor.sh, not
#     to root, so root cannot see them. Tear it down as that person while
#     install-anchor.sh still exists (step 3 removes the kit tree). Under sudo,
#     SUDO_USER names them; without it there is nobody to act as, and the note is
#     the fallback.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    _auid="$(id -u "$SUDO_USER" 2>/dev/null || true)"
    _anchor="$ROOT$APPROOT/install-anchor.sh"
    if [ -n "$_auid" ] && [ -x "$_anchor" ]; then
        if [ "$YES" = 1 ]; then
            say "tearing down the per-user reverse-bridge anchor for $SUDO_USER"
            sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="/run/user/$_auid" \
                "$_anchor" --uninstall 2>/dev/null \
                || say "  could not; run '$APPROOT/install-anchor.sh --uninstall' as $SUDO_USER"
        else
            say "would tear down the per-user reverse-bridge anchor for $SUDO_USER"
        fi
    fi
else
    say "note: if you set up the reverse-bridge anchor, run"
    say "  '$APPROOT/install-anchor.sh --uninstall' as yourself; it is a per-user"
    say "  service this root uninstall cannot see."
fi

# 2. Files the manifest says an installer created, except the kit tree's own
#    contents (the whole tree goes in step 3) and the realm CA (step 6, because
#    its removal has a trust-store refresh attached).
while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
        "$APPROOT"/*) continue ;;
        /usr/local/share/ca-certificates/*) continue ;;
        "$MANAGED_FILE") continue ;;
    esac
    if ! path_is_ours "$f"; then
        say "  left alone: $f (manifest names it, but it is not a path this kit owns)"
        continue
    fi
    # /etc/krb5.conf appears in created only when no file existed before the
    # kit wrote one, so deleting it is the restore.
    if [ -e "$ROOT$f" ]; then
        say "  remove $f (created by installer)"
        if [ "$YES" = 1 ]; then $SUDO rm -f "$ROOT$f"; fi
    fi
done < "$tmp/created"

# 3. The kit's own tree. The backups inside it are staged out first so step 5
#    can still restore them; the manifest dies with the tree, which is correct,
#    because after this run it no longer describes the machine.
if [ -d "$ROOT$APPROOT" ]; then
    say "  remove $APPROOT"
    if [ -d "$ROOT$APPROOT/backup" ]; then
        cp -pR "$ROOT$APPROOT/backup" "$tmp/staged-backup"
    fi
    # setup-macos.sh keeps the original krb5.conf here rather than in a
    # backup/ subdirectory, so stage that too or step 5 has nothing to
    # restore from.
    if [ -f "$ROOT$APPROOT/krb5.conf.orig" ]; then
        cp -p "$ROOT$APPROOT/krb5.conf.orig" "$tmp/krb5.conf.orig"
    fi
    if [ "$YES" = 1 ]; then $SUDO rm -rf "$ROOT$APPROOT"; fi
fi

# 3b. The realm CA in the macOS keychain. Note the algorithm: the installer
#     verified the download against its SHA-256, but delete-certificate
#     matches on SHA-1 only, so that is what the manifest records. Passing a
#     SHA-256 here matches nothing and reports success.
if [ -s "$tmp/cert_sha1" ]; then
    cert_sha1=$(cat "$tmp/cert_sha1")
    say "  remove the realm CA from the System keychain (SHA-1 $cert_sha1)"
    if [ "$YES" = 1 ] && [ -z "$ROOT" ]; then
        $SUDO security delete-certificate -t -Z "$cert_sha1" \
            /Library/Keychains/System.keychain \
            || say "  (delete-certificate failed; remove it in Keychain Access)"
    fi
fi

# 4. Packages, and only the ones the manifest says an installer put here. A
#    package recorded as already present is never named, not even in the plan.
if [ "$KEEP_PACKAGES" = 1 ]; then
    say "  packages: left alone (--keep-packages)"
elif [ -s "$tmp/packages" ]; then
    pkgs=""
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        pkgs="$pkgs $p"
        say "  remove package $p (installed by this kit)"
    done < "$tmp/packages"
    if [ "$YES" = 1 ] && [ -n "$pkgs" ]; then
        if [ -n "$ROOT" ]; then
            say "  (skipped under --root: package state belongs to the host, not the tree)"
        elif command -v apt-get >/dev/null 2>&1; then
            # shellcheck disable=SC2086  # pkgs is manifest-vetted and must word-split
            $SUDO env DEBIAN_FRONTEND=noninteractive apt-get -y remove $pkgs
        elif command -v dnf >/dev/null 2>&1; then
            # shellcheck disable=SC2086
            $SUDO dnf -y remove $pkgs
        else
            say "  (no known package manager - remove by hand:$pkgs)"
        fi
    fi
fi

# 5. Replaced files go back to the backup the first install run took.
while IFS="$(printf '\t')" read -r dst src; do
    [ -n "$dst" ] || continue
    if ! path_is_ours "$dst"; then
        say "  left alone: $dst (manifest names it, but it is not a path this kit owns)"
        continue
    fi
    staged="$tmp/staged-backup/$(basename "$src")"
    say "  restore $dst from $src"
    if [ "$YES" = 1 ]; then
        if [ -f "$staged" ]; then
            $SUDO cp -p "$staged" "$ROOT$dst"
        elif [ -f "$ROOT$src" ]; then
            $SUDO cp -p "$ROOT$src" "$ROOT$dst"
        else
            say "  WARNING: backup $src is missing - $dst was left as installed." >&2
        fi
    fi
done < "$tmp/replaced"

# 6. The realm CA, plus the refresh that actually removes it from the bundle.
while IFS= read -r f; do
    case "$f" in /usr/local/share/ca-certificates/*) ;; *) continue ;; esac
    if [ -e "$ROOT$f" ]; then
        say "  remove $f and refresh the trust store (update-ca-certificates --fresh)"
        if [ "$YES" = 1 ]; then
            $SUDO rm -f "$ROOT$f"
            if [ -z "$ROOT" ] && command -v update-ca-certificates >/dev/null 2>&1; then
                $SUDO update-ca-certificates --fresh >/dev/null
            fi
        fi
    fi
done < "$tmp/created"

# 7. Directories the manifest says an installer created, only if now empty.
while IFS= read -r d; do
    [ -n "$d" ] || continue
    path_is_ours "$d" || continue
    if [ "$YES" = 1 ] && [ -d "$ROOT$d" ]; then
        rmdir "$ROOT$d" 2>/dev/null || $SUDO rmdir "$ROOT$d" 2>/dev/null || true
    fi
done < "$tmp/created_dirs"

# 8. Tickets die with the kit; nothing above needed one.
say "  kdestroy"
if [ "$YES" = 1 ] && [ -z "$ROOT" ] && command -v kdestroy >/dev/null 2>&1; then
    kdestroy 2>/dev/null || true
fi

say ""
if [ "$YES" = 1 ]; then
    say "Done. If this machine was enrolled in FreeIPA, it still is: the host"
else
    say "Dry run: nothing was changed. Re-run with --yes to apply."
    say ""
    say "If this machine was enrolled in FreeIPA, uninstalling will not change that: the host"
fi
say "entry and host keytab remain on the IPA server. Un-enrolling is a separate,"
say "deliberate operation this script will never run for you:"
say "    sudo ipa-client-install --uninstall"
