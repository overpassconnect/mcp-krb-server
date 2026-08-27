#!/bin/sh
# setup.sh - enrol a machine in FreeIPA and provision the MCP client in one
# command. Published at /client/setup.sh by the publisher.
#
#   on IPA:     ipa host-add newbox.example.internal --random   # prints an OTP
#   on newbox:  curl -fsS https://mcp.example.internal/client/setup.sh -o /tmp/s.sh
#               sh /tmp/s.sh \
#                 --base-url https://mcp.example.internal/client \
#                 --mcp-url  https://mcp.example.internal/ \
#                 --hostname=newbox.example.internal \
#                 --server=ipa.example.internal --domain=example.internal \
#                 --realm=EXAMPLE.INTERNAL --password='<OTP>' --unattended
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
# copy. The API host is never assumed to be a download source, and neither URL
# has a default: a missing one is knowable from argv alone, so it is refused
# before anything is mutated.
#
# What authenticates the bytes: TLS, and nothing else. ipa-client-install runs
# before anything is downloaded, so by fetch time /etc/ipa/ca.crt is the CA
# this host was just enrolled against, and every fetch below is pinned to it
# with curl --cacert. That narrows the transport from "any public CA may vouch
# for the publisher" to "the realm CA must", which takes public-CA mis-issuance
# off the table. When the MCP host serves the bundle itself the pin still
# holds: its certificate is issued by the realm CA through the FreeIPA ACME
# service (verified on a live host). If the publisher's certificate does not
# chain to the realm CA, the fetch falls back to the system trust store and
# warns; at that point the pin is not in force.
#
# There is no signature over anything here. install-bridge.sh is fetched over
# TLS and executed as root, and the bridge it installs is fetched the same way,
# so whoever controls the publisher, or can terminate TLS for it with a
# certificate this machine accepts, decides what runs as root. Signing on the
# serving host would not close this: a key held by the publisher authenticates
# exactly the party TLS already authenticated. If a compromised publisher is in
# your threat model, build a signed RPM somewhere the serving host cannot reach
# and install it from an internal repo in your kickstart or base image
# (SECURITY.md [SC1]); curl-at-enrollment is the fallback path.
#
# All args except our own pass through to ipa-client-install; the
# company-standard --mkhomedir and --no-ntp are added if omitted, and
# pam_mkhomedir is enabled via pam-auth-update so home directories are created
# on first login. (On Debian/Ubuntu --mkhomedir alone does not wire
# pam_mkhomedir into PAM - this does; RHEL uses authselect and has no
# pam-auth-update, so it is skipped there.)
# Downloads go to a temp file rather than piping the network into a shell.
# Idempotent.
#
# Deliberately no hostnamectl call: ipa-client-install --hostname sets the
# system hostname itself, and adding one would break the documented getfqdn()
# default when the caller omits the flag. Whether the name then survives a
# reboot is the platform's business, not this script's: some container
# platforms rewrite /etc/hostname at every container start (Proxmox LXC writes
# back the short first label). The identity check at the end of phase 1
# catches a mismatch; making the name stick belongs at the platform layer.
set -eu

MCP_URL="${MCP_URL:-}"
BASE_URL="${MCP_BASE_URL:-}"

SKIP_MCP=0

# Strip our own flags out of the argument list; everything left over is passed
# to ipa-client-install unchanged. Consume exactly the original argc from the
# front and re-append the keepers at the back, so appended args are never
# re-examined (POSIX sh has no arrays).
argc=$#
while [ "$argc" -gt 0 ]; do
    arg="$1"; shift; argc=$((argc - 1))
    case "$arg" in
        --base-url)
            [ "$argc" -gt 0 ] || { echo "ERROR: --base-url needs a value" >&2; exit 2; }
            BASE_URL="$1"; shift; argc=$((argc - 1)) ;;
        --base-url=*) BASE_URL="${arg#--base-url=}" ;;
        --mcp-url)
            [ "$argc" -gt 0 ] || { echo "ERROR: --mcp-url needs a value" >&2; exit 2; }
            MCP_URL="$1"; shift; argc=$((argc - 1)) ;;
        --mcp-url=*) MCP_URL="${arg#--mcp-url=}" ;;
        --skip-mcp) SKIP_MCP=1 ;;
        *) set -- "$@" "$arg" ;;
    esac
done

# --- refuse everything knowable from argv before ipa-client-install ----------
#
# Enrolment is expensive and partly irreversible, so every argument error the
# MCP step would hit is raised first.
if [ "$SKIP_MCP" != 1 ]; then
    [ -n "$BASE_URL" ] || {
        echo "ERROR: --base-url is required to install the MCP client shim." >&2
        echo "  It is the publisher directory the client files are published under," >&2
        echo "  e.g. --base-url https://mcp.example.internal/client" >&2
        echo "  The MCP host serves the bundle at /client/ by default; if you served" >&2
        echo "  an exported copy elsewhere, point --base-url there. Do not assume." >&2
        echo "  To enrol in IPA only and install the shim later, pass --skip-mcp." >&2
        exit 2; }
    [ -n "$MCP_URL" ] || {
        echo "ERROR: --mcp-url is required to install the MCP client shim." >&2
        echo "  It is the Kerberized MCP API the bridge will talk to," >&2
        echo "  e.g. --mcp-url https://mcp.example.internal/" >&2
        echo "  To enrol in IPA only and install the shim later, pass --skip-mcp." >&2
        exit 2; }
    case "$BASE_URL" in
        https://*) ;;
        *) echo "ERROR: --base-url must start with https:// (got: $BASE_URL)" >&2; exit 2 ;;
    esac
    case "$MCP_URL" in
        https://*) ;;
        *) echo "ERROR: --mcp-url must start with https:// (got: $MCP_URL)" >&2; exit 2 ;;
    esac
fi
BASE_URL="${BASE_URL%/}"
INSTALL_URL="$BASE_URL/install-bridge.sh"

SUDO=""; [ "$(id -u)" != "0" ] && SUDO="sudo"

# ============================================================================
# PHASE 1 of 2: enrol this machine in FreeIPA.
# Joins the realm with ipa-client-install (installing the client package first
# if needed) and enables mkhomedir. Skipped cleanly if already enrolled; pass
# --skip-mcp to stop after this phase. Ends by checking that the kernel
# hostname matches the enrolled FQDN, because inbound GSSAPI depends on it.
# ============================================================================
# Which package (if any) this run installs is recorded for the manifest at the
# end of phase 2. Only a package this script installed may ever be removed by
# uninstall.sh; a machine that already had the IPA client keeps it, so nothing
# is recorded for that case and the package can never appear in a removal plan.
IPA_PKG_INSTALLED=""
if ! command -v ipa-client-install >/dev/null 2>&1; then
    if command -v dnf >/dev/null 2>&1; then
        if $SUDO dnf -y install ipa-client; then IPA_PKG_INSTALLED="ipa-client"
        else $SUDO dnf -y install freeipa-client; IPA_PKG_INSTALLED="freeipa-client"; fi
    elif command -v apt-get >/dev/null 2>&1; then
        # A freshly imaged box has never refreshed its package lists, so the
        # install below fails with "Unable to locate package freeipa-client".
        # Non-fatal: cached lists may still be good enough.
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update -qq \
            || echo "WARNING: apt-get update failed, continuing with cached lists" >&2
        # freeipa-client pulls in krb5-config, which debconf-prompts for the
        # realm and hangs an unattended run without DEBIAN_FRONTEND. Set via
        # `env` so it survives sudo's environment scrubbing.
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get -y install freeipa-client
        IPA_PKG_INSTALLED="freeipa-client"
    else echo "ERROR: ipa-client-install not found and no known package manager." >&2; exit 1; fi
fi

# Guarantee the company-standard flags even if the caller omits them.
case " $* " in *" --mkhomedir "*) ;; *) set -- --mkhomedir "$@" ;; esac
case " $* " in *" --no-ntp "*)    ;; *) set -- --no-ntp "$@"    ;; esac

if [ -f /etc/ipa/default.conf ]; then
    echo "Already IPA-enrolled - skipping ipa-client-install."
else
    $SUDO ipa-client-install "$@"
fi

# Create home directories on login (idempotent). Debian/Ubuntu needs this
# explicitly; skipped where pam-auth-update is absent (RHEL/authselect).
if command -v pam-auth-update >/dev/null 2>&1; then
    $SUDO pam-auth-update --enable mkhomedir \
        || echo "WARNING: pam-auth-update --enable mkhomedir failed - home dirs may not be created on login" >&2
fi

# --- host identity check ------------------------------------------------------
# GSSAPI acceptors on this machine (sshd above all) derive their name from the
# kernel hostname, so an enrolment whose FQDN and hostname disagree works today
# and silently rejects valid tickets later. Enrolment itself is already done
# either way; this refuses to call the run good while the identity is split.
IPA_HOST="$(sed -n 's/^host *= *//p' /etc/ipa/default.conf 2>/dev/null | head -n 1)"
SYS_FQDN="$(hostname -f 2>/dev/null || hostname)"
if [ -n "$IPA_HOST" ] && [ "$SYS_FQDN" != "$IPA_HOST" ]; then
    echo "ERROR: enrolment registered '$IPA_HOST' but this machine calls itself '$SYS_FQDN'." >&2
    echo "  SSH SSO onto this host will fail silently while the two disagree." >&2
    echo "  Fix:  hostnamectl set-hostname $IPA_HOST   then re-run this script." >&2
    echo "  In a container, also pin the name so the platform cannot revert it at the" >&2
    echo "  next start (on Proxmox LXC: touch /etc/.pve-ignore.hostname first)." >&2
    exit 1
fi
HOST_LABEL="${IPA_HOST:-$SYS_FQDN}"; HOST_LABEL="${HOST_LABEL%%.*}"
case "$HOST_LABEL" in
    ''|*[!0-9]*) ;;
    *)
        echo "WARNING: the first label of '${IPA_HOST:-$SYS_FQDN}' is all digits. glibc reads" >&2
        echo "         '$HOST_LABEL' as an IP address literal, so the short hostname can never" >&2
        echo "         resolve back to the FQDN, and anything that shortens the hostname" >&2
        echo "         (some container platforms do, at every start) breaks GSSAPI acceptors" >&2
        echo "         on this host. Prefer host names that start with a letter." >&2 ;;
esac
if command -v systemd-detect-virt >/dev/null 2>&1 \
        && [ "$(systemd-detect-virt 2>/dev/null || true)" = "lxc" ]; then
    echo "NOTE: this is an LXC container. Some platforms rewrite /etc/hostname at every" >&2
    echo "      container start (Proxmox LXC writes back the short first label), which" >&2
    echo "      reverts the FQDN and silently breaks SSH SSO after the next reboot. If" >&2
    echo "      that happens, re-check 'hostname -f'; on Proxmox pin the name with" >&2
    echo "      'touch /etc/.pve-ignore.hostname' before setting it." >&2
fi

# A shared host is where the reverse bridge's sockets land, forwarded by the
# workstation's ssh -R. Without StreamLocalBindUnlink the forwarded socket file
# outlives the session and the next connection cannot bind it: the forward works
# once and never again. Set it in a drop-in so the main sshd_config is untouched
# and uninstall can lift it by deleting one file. Harmless on a workstation, which
# simply never receives such a forward. Recorded in the manifest below.
STREAMLOCAL_DROPIN=""
if [ -d /etc/ssh/sshd_config.d ] && command -v sshd >/dev/null 2>&1; then
    _d=/etc/ssh/sshd_config.d/50-mcp-krb-streamlocal.conf
    if [ ! -f "$_d" ]; then
        printf '%s\n' '# Added by mcp-krb setup.sh: let the reverse-bridge socket forwarded by' \
            '# ssh -R rebind cleanly instead of failing once its file is left behind.' \
            'StreamLocalBindUnlink yes' | $SUDO tee "$_d" >/dev/null
        $SUDO chmod 0644 "$_d"
        # reload, not restart: this very session must not be dropped.
        $SUDO systemctl reload ssh 2>/dev/null \
            || $SUDO systemctl reload sshd 2>/dev/null || true
        echo "Set StreamLocalBindUnlink in $_d so reverse-bridge forwards rebind cleanly."
        STREAMLOCAL_DROPIN="$_d"
    fi
fi

# ============================================================================
# PHASE 2 of 2: install the MCP bridge.
# Fetches and runs install-bridge.sh, the same standalone script setup.ps1 and
# a human use; on a machine that is already enrolled, run install-bridge.sh
# directly instead of this file.
#
# IPA enrolment has already succeeded at this point, so a transient fetch
# failure must not look like a clean run: report exactly what is missing and
# how to finish by hand. Never -k: TLS is the only control on this leg.
# ============================================================================
if [ "$SKIP_MCP" = 1 ]; then
    echo "MCP client shim skipped (--skip-mcp). IPA enrolment is complete."
    echo "  install it later with:"
    echo "    sh $0 --base-url https://mcp.example.internal/client \\"
    echo "          --mcp-url https://mcp.example.internal/"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
installer="$work/install-bridge.sh"

# Pin the TLS leg to the realm CA: ipa-client-install has just run, so
# /etc/ipa/ca.crt is the CA this host was enrolled against. A publisher with a
# publicly issued certificate still works, by falling back once and announcing
# it, because failing closed here would strand hosts mid-enrolment; the warning
# is how the operator finds out the pin was not in force.
CURL_CA=""
CA_PIN_DROPPED=0
if [ -r /etc/ipa/ca.crt ]; then
    CURL_CA="--cacert /etc/ipa/ca.crt"
else
    echo "WARNING: /etc/ipa/ca.crt is not readable, so the realm CA pin is NOT in" >&2
    echo "         force for the download below. It falls back to the system trust" >&2
    echo "         store, where any publicly trusted CA can vouch for the publisher." >&2
fi

# shellcheck disable=SC2086  # CURL_CA is script-literal and must word-split
fetch() {
    # $1 = url, $2 = output path
    if curl --proto '=https' --tlsv1.2 -fsS --max-time 60 $CURL_CA -o "$2" "$1"; then
        return 0
    fi
    [ -n "$CURL_CA" ] || return 1
    # Distinguish "the realm CA does not sign this host" from "the host is down"
    # by retrying once with the system trust store. Announce it: the realm CA
    # pin is the only control on these bytes, and it just stopped applying.
    if curl --proto '=https' --tlsv1.2 -fsS --max-time 60 -o "$2" "$1"; then
        if [ "$CA_PIN_DROPPED" = 0 ]; then
            echo "WARNING: $1 does not validate against the realm CA (/etc/ipa/ca.crt)." >&2
            echo "         THE REALM CA PIN IS NOT IN FORCE for this download. It fell" >&2
            echo "         back to the system trust store, so any publicly trusted CA" >&2
            echo "         can vouch for the publisher, and nothing else checks these" >&2
            echo "         bytes. Fix the publisher's certificate, or accept that this" >&2
            echo "         leg is ordinary public-CA TLS." >&2
            CA_PIN_DROPPED=1
        fi
        CURL_CA=""
        return 0
    fi
    return 1
}

fetch_retry() {
    # $1 = url, $2 = output path. Three attempts; transient failures only.
    _a=1
    while [ "$_a" -le 3 ]; do
        if fetch "$1" "$2"; then return 0; fi
        echo "WARNING: attempt $_a of 3 failed to fetch $1" >&2
        _a=$((_a + 1))
        if [ "$_a" -le 3 ]; then sleep 5; fi
    done
    return 1
}

fetch_failed() {
    echo "ERROR: IPA enrolment SUCCEEDED but the MCP client shim was NOT installed." >&2
    echo "  failed URL: $1" >&2
    echo "  finish by hand once the publisher is reachable:" >&2
    echo "    sh $0 --base-url $BASE_URL --mcp-url $MCP_URL" >&2
    exit 1
}

fetch_retry "$INSTALL_URL" "$installer" || fetch_failed "$INSTALL_URL"

# Executed as root on TLS trust alone; nothing else checks these bytes.
sh "$installer" --managed --base-url "$BASE_URL" --mcp-url "$MCP_URL"

# install-bridge.sh has just written /opt/mcp-krb/install-manifest.json; fold
# in the one thing only this script knows, the enrolment-time package install,
# through the installer's own merge entry point so the merge rules live in one
# place. An older published installer without --manifest-merge is not worth
# failing an already-successful enrolment over: warn and move on, the cost is
# an uninstall that leaves that package alone.
# Fold what only this script knows into the manifest install-bridge.sh wrote:
# the enrolment-time package, and the sshd drop-in that lets forwards rebind.
_FRAG_PKG=""
[ -n "$IPA_PKG_INSTALLED" ] && _FRAG_PKG='"packages_installed": ["'"$IPA_PKG_INSTALLED"'"]'
_FRAG_CREATED=""
[ -n "$STREAMLOCAL_DROPIN" ] && _FRAG_CREATED='"created": ["'"$STREAMLOCAL_DROPIN"'"]'
if [ -n "$_FRAG_PKG" ] || [ -n "$_FRAG_CREATED" ]; then
    _SEP=""; [ -n "$_FRAG_PKG" ] && [ -n "$_FRAG_CREATED" ] && _SEP=", "
    $SUDO sh "$installer" --manifest-merge /opt/mcp-krb/install-manifest.json \
        '{"written_by": "setup.sh", '"$_FRAG_PKG$_SEP$_FRAG_CREATED"'}' \
        || echo "WARNING: could not update the install manifest - uninstall.sh may leave the package or the sshd drop-in behind." >&2
fi
