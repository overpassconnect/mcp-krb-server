#!/bin/sh
# run.sh - the single idempotent installer for the Kerberized MCP host.
#
# Runs as root on a host that is already IPA-enrolled. It replaces the ad-hoc
# root-shell steps that built the first server by hand: package installs, the
# venv, the keytab, the rendered unit and vhost, the certificate, the renewal
# hook and the final verification.
#
#   sudo sh server/install/run.sh --site-env /etc/mcp-server/site.env
#
# Contains no site literals. Every value comes from a flag or from site.env, and
# an unset required value is a hard error rather than a silent example.internal.
#
# Every step is a no-op on re-run. Anything that needs IPA admin rights is printed
# for a human to run; this script never asks for or stores a password, and never
# obtains an admin ticket itself.
set -eu

# --------------------------------------------------------------------------
# defaults and flags
# --------------------------------------------------------------------------
SITE_ENV="${SITE_ENV:-/etc/mcp-server/site.env}"
FQDN=""; REALM=""; IPA_SERVER=""
MCP_VENV=""; SVCUSER=""; SVCGROUP=""; WEBROOT=""
NO_SERVE_CLIENT=0; CLIENT_EXPORT=""
CLIENT_SITE_SECTIONS=""; CLIENT_DOWNLOAD_BASE=""; CLIENT_CA_INSTALL=""; CLIENT_PATH=""; CLIENT_ROOT=""
CLIENT_ORG_NAME=""; CLIENT_SUPPORT_EMAIL=""; CLIENT_DNS_IP=""
ACME_DIRECTORY=""; ACME_EMAIL=""; ACME_RSA_KEY_SIZE=""
CERT_MODE="acme"; CERT_PATH=""; WHEELHOUSE=""
ROTATE_KEYTAB=0; CREATE_IPA_SERVICE=0; DRY_RUN=0; FORCE_UNIT=0; ENABLE_AUTHZ_EDITOR=0

usage() {
    cat <<'USAGE'
usage: run.sh [options]

  --site-env FILE        site parameter file (default /etc/mcp-server/site.env)
  --fqdn HOST            this server's FQDN            (site.env: MCP_HOST)
  --realm REALM          Kerberos realm, UPPERCASE     (site.env: REALM)
  --ipa-server HOST      IPA server for ipa-getkeytab  (site.env: IPA_SERVER)
  --venv DIR             python venv path              (site.env: MCP_VENV)
  --user NAME            service account               (site.env: SVCUSER)
  --group NAME           service group                 (site.env: SVCGROUP)
  --webroot DIR          http-01 challenge docroot     (site.env: WEBROOT)
  --no-serve-client      do NOT serve the client bundle from this host.
                         By default this host serves the client files and
                         the provisioning page at /client/, so a fresh install
                         needs nothing extra. This turns that off, leaving the
                         vhost byte-identical to one that never had the feature.
                                                       (site.env: SERVE_CLIENT=no)
  --client-site-sections FILE
                         HTML fragment of extra <section> blocks to inject into
                         the provisioning page, for content specific to this
                         deployment. Nav entries are derived from each section's
                         id and <h2>. Must be root-owned and not group-writable:
                         it becomes markup on a page that tells people what to
                         run as root.        (site.env: CLIENT_SITE_SECTIONS)
  --client-export DIR    also assemble the bundle into DIR, a local folder, for
                         copying off-band to wherever you serve static files.
                         Independent of serving here.  (site.env: CLIENT_EXPORT)
  --client-path PATH     URL path when serving, default /client/  (site.env: CLIENT_PATH)
  --client-root DIR      docroot when serving, default /var/www/client
                                                       (site.env: CLIENT_ROOT)
  --client-org-name STR  display name on the page (default: derived from realm)
                                                       (site.env: CLIENT_ORG_NAME)
  --client-support-email ADDR   page contact, optional (site.env: CLIENT_SUPPORT_EMAIL)
  --client-download-base URL_OR_PATH
                         where the files are, if NOT beside the page. A host
                         serving a landing page at / and artifacts under /d/
                         needs '/d'; the page infers its own directory
                         otherwise.        (site.env: CLIENT_DOWNLOAD_BASE)
  --client-ca-install yes|no
                         whether the provisioning flow installs the realm CA
                         into the workstation's trust store. Default yes. Set
                         no where the CA arrives another way, MDM or a golden
                         image, so the page stops telling people to do it a
                         second time.       (site.env: CLIENT_CA_INSTALL)
  --client-dns-ip IP     resolver for the macOS split-DNS snippet, optional
                         (default: derived from this host)  (site.env: CLIENT_DNS_IP)
  --cert-mode MODE       acme (default) | existing | none
  --acme-directory URL   internal ACME directory       (site.env: ACME_DIRECTORY)
  --cert-path DIR        directory holding fullchain.pem/privkey.pem.
                         ONLY valid with --cert-mode existing; any other mode is
                         a hard error rather than a silently ignored flag.
  --wheelhouse DIR       offline pip wheel directory
  --rotate-keytab        re-retrieve the keytab (BUMPS THE KVNO, breaks live tickets)
  --create-ipa-service   run `ipa service-add` if the SPN is missing (needs an admin ticket)
  --force-unit           overwrite a locally edited unit instead of aborting
  --enable-authz-editor  serve the web policy editor. A FLAG, never a site.env
                         key: it is an authenticated write surface over tool
                         authorization, so whoever runs the installer must ask
                         for it, and automation driven from a config file cannot
                         turn it on. Requires MCP_POLICY_ADMINS in site.env.
  --dry-run              print what would change, mutate nothing
  -h, --help             this text

REALM is never inferred from the FQDN. It comes only from --realm or site.env.

--fqdn, --realm and --ipa-server may not DISAGREE with a site.env that also sets
them. This script execs server/install/verify.sh, which reads the same file, so a
disagreement would build the host from the flags and verify it against the file.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --site-env)         SITE_ENV="$2"; shift ;;
        --fqdn)             FQDN="$2"; shift ;;
        --realm)            REALM="$2"; shift ;;
        --ipa-server)       IPA_SERVER="$2"; shift ;;
        --venv)             MCP_VENV="$2"; shift ;;
        --user)             SVCUSER="$2"; shift ;;
        --group)            SVCGROUP="$2"; shift ;;
        --webroot)          WEBROOT="$2"; shift ;;
        --no-serve-client)  NO_SERVE_CLIENT=1 ;;
        --client-site-sections)   CLIENT_SITE_SECTIONS="$2"; shift ;;
        --client-site-sections=*) CLIENT_SITE_SECTIONS="${1#--client-site-sections=}" ;;
        --client-export)    CLIENT_EXPORT="$2"; shift ;;
        --client-export=*)  CLIENT_EXPORT="${1#--client-export=}" ;;
        --client-path)      CLIENT_PATH="$2"; shift ;;
        --client-path=*)    CLIENT_PATH="${1#--client-path=}" ;;
        --client-root)      CLIENT_ROOT="$2"; shift ;;
        --client-root=*)    CLIENT_ROOT="${1#--client-root=}" ;;
        --client-org-name)  CLIENT_ORG_NAME="$2"; shift ;;
        --client-org-name=*) CLIENT_ORG_NAME="${1#--client-org-name=}" ;;
        --client-support-email)   CLIENT_SUPPORT_EMAIL="$2"; shift ;;
        --client-support-email=*) CLIENT_SUPPORT_EMAIL="${1#--client-support-email=}" ;;
        --client-download-base)   CLIENT_DOWNLOAD_BASE="$2"; shift ;;
        --client-download-base=*) CLIENT_DOWNLOAD_BASE="${1#--client-download-base=}" ;;
        --client-ca-install)   CLIENT_CA_INSTALL="$2"; shift ;;
        --client-ca-install=*) CLIENT_CA_INSTALL="${1#--client-ca-install=}" ;;
        --client-dns-ip)    CLIENT_DNS_IP="$2"; shift ;;
        --client-dns-ip=*)  CLIENT_DNS_IP="${1#--client-dns-ip=}" ;;
        --cert-mode)        CERT_MODE="$2"; shift ;;
        --acme-directory)   ACME_DIRECTORY="$2"; shift ;;
        --cert-path)        CERT_PATH="$2"; shift ;;
        --wheelhouse)       WHEELHOUSE="$2"; shift ;;
        --rotate-keytab)    ROTATE_KEYTAB=1 ;;
        --create-ipa-service) CREATE_IPA_SERVICE=1 ;;
        --force-unit)       FORCE_UNIT=1 ;;
        --enable-authz-editor) ENABLE_AUTHZ_EDITOR=1 ;;
        --dry-run)          DRY_RUN=1 ;;
        -h|--help)          usage; exit 0 ;;
        *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
# Every mutation goes through run(), so --dry-run covers every change.
run()  { if [ "$DRY_RUN" = 1 ]; then printf '  would run: %s\n' "$*"; else "$@"; fi; }

# Every template in this repo carries explicit {{TOKEN}} placeholders, and every
# render is checked with this before the file is installed. A pattern-matching
# sed cannot report that it matched nothing; this check can.
assert_no_tokens() {
    _f="$1"
    if grep -qE '\{\{[A-Z0-9_]+\}\}' "$_f"; then
        say "--- unsubstituted tokens in $_f ---"
        grep -nE '\{\{[A-Z0-9_]+\}\}' "$_f" >&2 || true
        die "rendering left placeholder tokens in $_f (see above). Refusing to install it."
    fi
    return 0
}

# --------------------------------------------------------------------------
# Source-tree safety.
#
# This script runs as root, installs $SERVERDIR/*.py into /opt/mcp-server where
# a service executes them, and renders the unit and the vhost from the same
# tree. If the tree, or any directory above it, is writable by a non-root user,
# that user chooses what root runs. The documented workflow is `git pull` into
# a home directory, which is exactly the shape this refuses.
#
# It runs first, before the first mutation. A later copy of this same walk once
# lived in the last step of the run, and by the time it aborted the python was
# already installed and the hook had already been run as root.
#
# The walk below is upward only, and both of its find(1) calls use -maxdepth 0,
# so on its own it examines one inode per iteration: $SRC itself, then each
# parent. It once never looked at any file inside the tree while the line that
# reported it claimed the whole tree had been checked: a root-owned 0755 $SRC
# containing a group-writable server/ (one hand-run chmod -R, a restored
# archive, a tarball unpacked with odd modes) passed silently, and the user who
# could write that subdirectory chose mcp_server.py, the rendered unit and the
# rendered vhost, all of which root installs or executes. A check that
# overstates what it verified is worse than no check, because it ends the
# reviewer's search. The downward pass below closes that gap, and the PASS
# message says exactly what both passes cover.
assert_root_owned_tree() {
    _p="$(CDPATH= cd -- "$1" && pwd)" || die "cannot resolve source directory: $1"
    _tree="$_p"
    while :; do
        [ "$(find "$_p" -maxdepth 0 ! -user root)" = "" ] \
            || die "$_p is not owned by root, and this installer executes code from that tree as root.
  Install from a root-owned copy:  sudo cp -a <tree> /usr/local/src/mcp-krb-server
  then run this script from there. Nothing has been changed."
        [ "$(find "$_p" -maxdepth 0 \( -perm -g+w -o -perm -o+w \))" = "" ] \
            || die "$_p is group- or world-writable, and this installer executes code from that tree as root.
  Install from a root-owned copy:  sudo cp -a <tree> /usr/local/src/mcp-krb-server
  then run this script from there. Nothing has been changed."
        [ "$_p" != "/" ] || break
        _p="$(dirname "$_p")"
    done
    # Downward pass: one traversal of the tree itself, stopping at the first
    # offending path. -xdev keeps it on one filesystem; -print -quit ends the
    # walk early instead of taking a full inventory.
    #
    # This line used to end `2>/dev/null) || _bad=""`. That silenced find's
    # diagnostics and turned any find failure (an unreadable subdirectory, a
    # traversal that could not complete) into an empty result, indistinguishable
    # here from "nothing offending was found"; the run then printed the PASS
    # line below claiming every path inside the tree had been checked when the
    # traversal had aborted partway. With `set -e` a find that cannot complete
    # now stops the run, before the first mutation, rather than being reported
    # as a clean tree.
    _bad="$(find "$_tree" -xdev \( ! -user root -o -perm -g+w -o -perm -o+w \) -print -quit)"
    [ -z "$_bad" ] || die "$_bad is inside the source tree and is either not owned by root or is
  group- or world-writable, and this installer executes code from that tree as root.
  Whoever can write that path chooses what root runs here.
  Fix it, or install from a root-owned copy:
    sudo cp -a <tree> /usr/local/src/mcp-krb-server
  then run this script from there. Nothing has been changed."
    return 0
}

# One temp tree for the whole run, removed on every exit path. Nothing this
# script writes outside of it is ever a partial file: renders are staged here
# and moved into place with install(1).
TMPROOT="$(mktemp -d)"
RENDER="$TMPROOT/render"
CCDIR="$TMPROOT/cc"
mkdir -p "$RENDER" "$CCDIR"
# kdestroy is scoped to the private ccache this script creates in step 5, never
# to the ambient default one. It used to fire whenever KRB5CCNAME was non-empty,
# which on the common idempotent re-run (keytab already correct, so step 5 never
# assigns KRB5CCNAME) meant the operator's own exported admin ccache: the admin
# ticket needed for --create-ipa-service vanished between runs for a reason
# nothing printed.
cleanup() {
    [ -f "$CCDIR/ccache" ] && kdestroy -q -c "FILE:$CCDIR/ccache" >/dev/null 2>&1
    rm -rf "$TMPROOT"
    return 0
}

# The vhost rollback must fire on a signal as well as on die().
#
# From the moment step 8 places the HTTP-only bootstrap stub until step 9
# accepts the full vhost, the live configuration is this run's
# `location / { return 404; }` on :80 with no :443 listener at all. Every die()
# in that window routes through die_vhost and puts back what was found on disk.
# A signal used to route through nothing but cleanup(), which only kdestroys
# the private ccache and removes $TMPROOT. The window spans the ACME directory
# probe and the whole of certbot, which routinely runs for minutes and is the
# thing an operator is most likely to interrupt, so a Ctrl-C, an SSH disconnect
# or a job timeout left a serving host answering 404 with a perfectly good
# $VHOST_AVAIL.bak sitting unused beside it and no output saying so. Worse:
# cleanup() deleted $TMPROOT (which holds $RENDER/mcp.conf) and returned rather
# than exiting, so a shell that resumes after a non-EXIT trap carried on into
# step 9 and failed on a render that no longer existed, mid-mutation.
#
# Declared here, before the trap is armed, so the handler can never read an
# unset variable under `set -u`. restore_vhost() and place_vhost() are defined
# later in step 7; VHOST_ROLLBACK_ARMED is 0 until place_vhost has actually put
# a file on disk, which is the only state in which the handler calls them.
VHOST_ROLLBACK_ARMED=0
RESTORED="the vhost was not modified by this run, so nothing needed restoring"
on_signal() {
    _sig="$1"; _code="$2"
    # Disarm first: a second signal during the rollback must not re-enter this.
    trap - EXIT INT TERM HUP
    if [ "$VHOST_ROLLBACK_ARMED" = 1 ]; then
        restore_vhost
        printf 'INTERRUPTED by SIG%s while this run had the temporary bootstrap vhost live.\n  %s\n' \
            "$_sig" "$RESTORED" >&2
    else
        printf 'INTERRUPTED by SIG%s. The nginx configuration was not modified by this run.\n' \
            "$_sig" >&2
    fi
    cleanup
    exit "$_code"
}
trap cleanup EXIT
trap 'on_signal INT 130'  INT
trap 'on_signal TERM 143' TERM
trap 'on_signal HUP 129'  HUP

# This script lives in <repo>/server/install/, so the repo root is two levels
# up. It used to live in <repo>/server/ with a single '..'; the move left that
# resolving to <repo>/server/server, which does not exist, so every invocation
# died on the check below. Both directories are derived explicitly.
SRC="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SERVERDIR="$SRC/server"          # the Python that runs
INSTALLDIR="$SERVERDIR/install"   # the unit, vhost and site.env template
[ -d "$SERVERDIR" ] && [ -f "$SERVERDIR/mcp_server.py" ] \
    || die "cannot locate the repo: expected $SERVERDIR/mcp_server.py"
[ -d "$INSTALLDIR" ] && [ -f "$INSTALLDIR/mcp-server.service" ] \
    || die "cannot locate the deploy templates: expected $INSTALLDIR/mcp-server.service"

# --------------------------------------------------------------------------
# site.env: flags win, then the file, then a hard error. Never a default host.
#
# The flag values are stashed first, because sourcing site.env assigns the same
# variable names and would otherwise silently overwrite anything passed on the
# command line.
# --------------------------------------------------------------------------
ARG_FQDN="$FQDN"; ARG_REALM="$REALM"; ARG_IPA_SERVER="$IPA_SERVER"
ARG_VENV="$MCP_VENV"; ARG_USER="$SVCUSER"; ARG_ACME_DIRECTORY="$ACME_DIRECTORY"
ARG_GROUP="$SVCGROUP"; ARG_WEBROOT="$WEBROOT"
ARG_CERT_MODE="$CERT_MODE"
ARG_NO_SERVE_CLIENT="$NO_SERVE_CLIENT"; ARG_CLIENT_EXPORT="$CLIENT_EXPORT"
ARG_CLIENT_PATH="$CLIENT_PATH"; ARG_CLIENT_ROOT="$CLIENT_ROOT"
ARG_CLIENT_ORG_NAME="$CLIENT_ORG_NAME"; ARG_CLIENT_SUPPORT_EMAIL="$CLIENT_SUPPORT_EMAIL"
ARG_CLIENT_DNS_IP="$CLIENT_DNS_IP"
ARG_CLIENT_SITE_SECTIONS="$CLIENT_SITE_SECTIONS"
ARG_CLIENT_DOWNLOAD_BASE="$CLIENT_DOWNLOAD_BASE"
ARG_CLIENT_CA_INSTALL="$CLIENT_CA_INSTALL"

if [ -f "$SITE_ENV" ]; then
    # shellcheck disable=SC1090
    . "$SITE_ENV"
    say "site parameters: $SITE_ENV"
else
    say "no site.env at $SITE_ENV - relying entirely on flags"
fi

# --------------------------------------------------------------------------
# Bidirectional alias resolution, in one place, immediately after sourcing.
#
# MCP_HOST/IPA_SERVER are canonical; MCP_FQDN/IPA_FQDN are accepted aliases.
# Setting either name of a pair must populate the other, and it must happen
# here rather than at each use site. This once resolved one way only: a
# site.env that set only MCP_FQDN, which is the name verify.sh's own docs use,
# died at the FQDN check below while the value sat correctly in the file.
# Conflicting values are a hard error rather than a silent pick, because there
# is no defensible winner.
#
# There is no separate download host to name here. This host serves the client
# bundle itself by default, and an exported bundle is copied off-band by the
# operator with their own tools, so the installer needs no address for it.
# --------------------------------------------------------------------------
alias_pair() {
    _canon_name="$1"; _canon="$2"; _alias_name="$3"; _alias="$4"
    if [ -n "$_canon" ] && [ -n "$_alias" ] && [ "$_canon" != "$_alias" ]; then
        die "$SITE_ENV sets $_canon_name='$_canon' and $_alias_name='$_alias'.
  They are two names for one value. Set one, or set both to the same string."
    fi
    # Written as an if/else, not an && chain: a failing AND-list as the last
    # statement of a function is exactly the shape that trips `set -e`.
    if [ -n "$_canon" ]; then
        printf '%s\n' "$_canon"
    else
        printf '%s\n' "$_alias"
    fi
    return 0
}
MCP_HOST="$(alias_pair MCP_HOST "${MCP_HOST:-}" MCP_FQDN "${MCP_FQDN:-}")"
IPA_SERVER="$(alias_pair IPA_SERVER "${IPA_SERVER:-}" IPA_FQDN "${IPA_FQDN:-}")"
MCP_FQDN="$MCP_HOST"; IPA_FQDN="$IPA_SERVER"
export MCP_FQDN IPA_FQDN MCP_HOST IPA_SERVER

# What the file said, snapshotted before the flags are layered on top. For
# these three keys a flag that disagrees with the file is a split brain: this
# host gets the flag while verify.sh, which reads the file itself, reports on
# the file. See the refusal in step 0.
FILE_MCP_HOST="${MCP_HOST:-}"
FILE_REALM="${REALM:-}"
FILE_IPA_SERVER="${IPA_SERVER:-}"

FQDN="${ARG_FQDN:-${MCP_HOST:-}}"
REALM="${ARG_REALM:-${REALM:-}}"
IPA_SERVER="${ARG_IPA_SERVER:-${IPA_SERVER:-}}"
MCP_VENV="${ARG_VENV:-${MCP_VENV:-/opt/mcp-venv}}"
SVCUSER="${ARG_USER:-${SVCUSER:-mcp}}"
# SVCGROUP defaults to SVCUSER, so `--user mcpsvc` alone yields mcpsvc:mcpsvc
# rather than mcpsvc:mcp. Whatever is resolved here is what actually gets
# created, and what the keytab is chowned to.
SVCGROUP="${ARG_GROUP:-${SVCGROUP:-$SVCUSER}}"
WEBROOT="${ARG_WEBROOT:-${WEBROOT:-/var/www/html}}"
ACME_DIRECTORY="${ARG_ACME_DIRECTORY:-${ACME_DIRECTORY:-}}"
ACME_EMAIL="${ACME_EMAIL:-}"
ACME_RSA_KEY_SIZE="${ACME_RSA_KEY_SIZE:-4096}"
CERT_MODE="${ARG_CERT_MODE:-acme}"
CERT_NAME="${MCP_CERT_NAME:-$FQDN}"

# Client bundle. Serving it from this host is the default: a fresh install hands
# workstations everything they need at /client/, the page included, with no extra
# flags. --no-serve-client (or SERVE_CLIENT=no) turns that off, leaving the vhost
# byte-identical to one that never had the feature. --client-export DIR writes the
# same bundle to a local folder to copy off-band, independent of serving here.
if [ "$ARG_NO_SERVE_CLIENT" = 1 ]; then
    SERVE_CLIENT=no
else
    case "$(printf '%s' "${SERVE_CLIENT:-yes}" | tr 'A-Z' 'a-z')" in
        no|0|false|off) SERVE_CLIENT=no ;;
        yes|1|true|on|'') SERVE_CLIENT=yes ;;
        *) die "SERVE_CLIENT must be yes or no (got '${SERVE_CLIENT}')" ;;
    esac
fi
CLIENT_EXPORT="${ARG_CLIENT_EXPORT:-${CLIENT_EXPORT:-}}"
CLIENT_PATH="${ARG_CLIENT_PATH:-${CLIENT_PATH:-/client/}}"
CLIENT_ROOT="${ARG_CLIENT_ROOT:-${CLIENT_ROOT:-/var/www/client}}"
CLIENT_SITE_SECTIONS="${ARG_CLIENT_SITE_SECTIONS:-${CLIENT_SITE_SECTIONS:-}}"
CLIENT_DOWNLOAD_BASE="${ARG_CLIENT_DOWNLOAD_BASE:-${CLIENT_DOWNLOAD_BASE:-}}"
CLIENT_CA_INSTALL="${ARG_CLIENT_CA_INSTALL:-${CLIENT_CA_INSTALL:-yes}}"
case "$CLIENT_CA_INSTALL" in
    yes|no) ;;
    *) die "CLIENT_CA_INSTALL must be yes or no, got '$CLIENT_CA_INSTALL'." ;;
esac
CLIENT_ORG_NAME="${ARG_CLIENT_ORG_NAME:-${CLIENT_ORG_NAME:-}}"
CLIENT_SUPPORT_EMAIL="${ARG_CLIENT_SUPPORT_EMAIL:-${CLIENT_SUPPORT_EMAIL:-}}"
CLIENT_DNS_IP="${ARG_CLIENT_DNS_IP:-${CLIENT_DNS_IP:-}}"

if [ "$SERVE_CLIENT" = yes ]; then
    # A location prefix, so both slashes matter: nginx matches the leading one
    # and 'root' appends the rest of the URI to the docroot.
    case "$CLIENT_PATH" in
        /*/) ;;
        *) die "--client-path must start and end with '/' (got '$CLIENT_PATH')" ;;
    esac
    case "$CLIENT_ROOT" in
        /*) ;;
        *) die "--client-root must be an absolute path (got '$CLIENT_ROOT')" ;;
    esac
    # The MCP protocol is proxied from '/', so a client path that collided with
    # it would shadow the API for every request underneath.
    case "$CLIENT_PATH" in
        /) die "--client-path cannot be '/': that is where the MCP API is served" ;;
    esac
fi
if [ -n "$CLIENT_EXPORT" ]; then
    case "$CLIENT_EXPORT" in
        /*) ;;
        *) die "--client-export must be an absolute path (got '$CLIENT_EXPORT')" ;;
    esac
fi

# site.env is sourced without exporting, so REALM is exported explicitly, after
# resolution: what crosses into anything this script runs is the value this run
# actually used rather than whatever the file happened to say.
export REALM

[ -n "$FQDN" ]  || die "no FQDN: pass --fqdn or set MCP_HOST in $SITE_ENV"
[ -n "$REALM" ] || die "no realm: pass --realm or set REALM in $SITE_ENV (never inferred from the FQDN)"

case "$CERT_MODE" in acme|existing|none) ;; *) die "--cert-mode must be acme, existing or none" ;; esac

CONFDIR="/etc/mcp-server"
KEYTAB="$CONFDIR/krb5.keytab"
CODEDIR="/opt/mcp-server"
UNIT="/etc/systemd/system/mcp-server.service"
# Where we remember the exact unit we last installed, so a later run can tell
# "the template changed" apart from "an operator edited the live unit".
STAMPDIR="/var/lib/mcp-server-install"
MCP_SPN_KRB="HTTP/$FQDN@$REALM"
CERTDIR="/etc/letsencrypt/live/$CERT_NAME"
# --cert-path used to be accepted, never validated, and silently discarded
# unless --cert-mode was exactly 'existing'. `--cert-path /srv/pki/mcp` on its
# own, or with the documented `--cert-mode none`, left CERTDIR pointing at
# /etc/letsencrypt/live/$CERT_NAME; the vhost render and the ssl_certificate
# assertion both derive from CERTDIR, so they agreed with each other and the
# run reported PASS while aiming nginx at the one directory the operator had
# explicitly told it not to use. The combination is refused instead.
if [ -n "$CERT_PATH" ]; then
    [ "$CERT_MODE" = existing ] || die "--cert-path $CERT_PATH was given with --cert-mode $CERT_MODE.
  --cert-path is only honoured by --cert-mode existing, and silently ignoring it
  would point nginx at /etc/letsencrypt/live/$CERT_NAME instead. Either add
  --cert-mode existing, or drop --cert-path. Nothing has been changed."
    case "$CERT_PATH" in /*) ;; *) die "--cert-path must be an absolute path, got '$CERT_PATH'" ;; esac
    case "$CERT_PATH" in *[!a-zA-Z0-9._/-]*)
        die "--cert-path contains characters this installer will not substitute safely: '$CERT_PATH'" ;;
    esac
    CERTDIR="$CERT_PATH"
fi

say "host:      $FQDN"
say "realm:     $REALM"
say "venv:      $MCP_VENV"
say "service:   $SVCUSER:$SVCGROUP"
say "cert mode: $CERT_MODE"
[ "$DRY_RUN" = 1 ] && say "DRY RUN: nothing will be changed"

# --------------------------------------------------------------------------
# 0. PREFLIGHT. Fail with the exact remediation; never auto-fix anything that
#    needs IPA admin rights.
# --------------------------------------------------------------------------
step "0. preflight"

[ "$(id -u)" = 0 ] || die "must run as root"

assert_root_owned_tree "$SRC"
say "PASS source tree $SRC, every path inside it, and every parent are root-owned"
say "     and not group/world-writable"

# A flag that disagrees with site.env for these three keys is refused, because
# it can only be half obeyed: this script sources site.env without exporting
# and then execs server/install/verify.sh, which reads the same file for any
# value the installer did not hand it. So `--fqdn mcp2` built the keytab, the
# certificate, the unit and the vhost for mcp2 while the verifier answered
# about the file's host - and if that host also existed, the checks passed
# against the wrong machine with zero errors.
if [ -f "$SITE_ENV" ]; then
    _conflict=""
    [ -n "$ARG_FQDN" ]       && [ -n "$FILE_MCP_HOST" ]  && [ "$ARG_FQDN" != "$FILE_MCP_HOST" ] \
        && _conflict="$_conflict
  --fqdn '$ARG_FQDN' vs MCP_HOST '$FILE_MCP_HOST'"
    [ -n "$ARG_REALM" ]      && [ -n "$FILE_REALM" ]     && [ "$ARG_REALM" != "$FILE_REALM" ] \
        && _conflict="$_conflict
  --realm '$ARG_REALM' vs REALM '$FILE_REALM'"
    [ -n "$ARG_IPA_SERVER" ] && [ -n "$FILE_IPA_SERVER" ] && [ "$ARG_IPA_SERVER" != "$FILE_IPA_SERVER" ] \
        && _conflict="$_conflict
  --ipa-server '$ARG_IPA_SERVER' vs IPA_SERVER '$FILE_IPA_SERVER'"
    [ -n "$_conflict" ] && die "these flags disagree with $SITE_ENV:$_conflict
  This host would be built from the flags while server/install/verify.sh, which
  reads $SITE_ENV directly, would report on the file's values.
  Edit $SITE_ENV, or point --site-env at a different file, or drop the flags.
  Nothing has been changed."
fi

case "$FQDN$REALM" in
    *example.internal*|*EXAMPLE.INTERNAL*)
        die "refusing to install with placeholder values ($FQDN / $REALM). Fill in $SITE_ENV." ;;
esac
case "$FQDN" in *.*) ;; *) die "--fqdn must be a fully qualified domain name, got '$FQDN'" ;; esac

# SVCUSER, SVCGROUP and WEBROOT are substituted into templates with sed, so a
# value containing a delimiter or a regex metacharacter would corrupt the
# render instead of failing; the shape is validated up front.
case "$SVCUSER"  in *[!a-zA-Z0-9._-]*|"") die "invalid service user name: '$SVCUSER'" ;; esac
case "$SVCGROUP" in *[!a-zA-Z0-9._-]*|"") die "invalid service group name: '$SVCGROUP'" ;; esac
case "$WEBROOT"  in /*) ;; *) die "WEBROOT must be an absolute path, got '$WEBROOT'" ;; esac
case "$WEBROOT"  in *[!a-zA-Z0-9._/-]*) die "WEBROOT contains characters this installer will not substitute safely: '$WEBROOT'" ;; esac
case "$CERTDIR"  in /*) ;; *) die "certificate directory must be absolute, got '$CERTDIR'" ;; esac
case "$CERTDIR"  in *[!a-zA-Z0-9._/-]*) die "certificate directory contains characters this installer will not substitute safely: '$CERTDIR'" ;; esac

if command -v apt-get >/dev/null 2>&1;  then PKGMGR=apt
elif command -v dnf >/dev/null 2>&1;    then PKGMGR=dnf
else die "no supported package manager (apt-get or dnf) found"; fi
say "PASS package manager: $PKGMGR"

[ -f /etc/ipa/default.conf ] || die "host is not IPA-enrolled (/etc/ipa/default.conf missing).
  Enrol it first with ipa-client-install, then re-run this script."
if [ -z "$IPA_SERVER" ]; then
    IPA_SERVER="$(sed -n 's/^server *= *//p' /etc/ipa/default.conf | head -1)"
fi
IPA_REALM="$(sed -n 's/^realm *= *//p' /etc/ipa/default.conf | head -1)"
[ -n "$IPA_REALM" ] && [ "$IPA_REALM" != "$REALM" ] \
    && die "realm mismatch: $SITE_ENV says '$REALM' but /etc/ipa/default.conf says '$IPA_REALM'"
[ -n "$IPA_SERVER" ] || die "no IPA server: pass --ipa-server or set IPA_SERVER in $SITE_ENV"
say "PASS IPA enrolment: server=$IPA_SERVER realm=$REALM"

[ -f /etc/krb5.keytab ] || die "/etc/krb5.keytab missing: the host principal is required to fetch the service keytab"
say "PASS host keytab present"

# The system hostname has to match, or gssapi accepts for a name nobody requests.
SYSFQDN="$(hostname -f 2>/dev/null || hostname)"
[ "$SYSFQDN" = "$FQDN" ] || die "system FQDN is '$SYSFQDN' but --fqdn is '$FQDN'.
  Fix the hostname (hostnamectl set-hostname $FQDN) and /etc/hosts, then re-run."
# The success line sits inside the guard that does the lookup. It used to sit
# outside it, so a host with no getent(1) printed "PASS hostname and forward DNS
# agree" having resolved nothing at all. A skipped check must announce itself as
# skipped; it must never borrow the wording of a check that ran.
if command -v getent >/dev/null 2>&1; then
    getent hosts "$FQDN" >/dev/null 2>&1 || die "forward DNS does not resolve $FQDN"
    say "PASS hostname matches and forward DNS resolves $FQDN"
else
    say "SKIPPED forward DNS check: getent(1) is not present on this host."
    say "PASS hostname matches $FQDN (DNS was NOT checked)"
fi

# ---- shape of the values this host is built from ----------------------------
#
# Presence is already enforced above: $FQDN, $REALM and $IPA_SERVER each have a
# die() of their own, and the placeholder refusal covers $FQDN and $REALM.
# Shape still matters here: $FQDN becomes the nginx server_name, the HTTP/
# service principal and the certificate lineage, and $IPA_SERVER is what
# ipa-getkeytab is pointed at. A trailing dot, an underscore or a capital
# letter yields a keytab and a vhost that look installed and authenticate
# nothing.
#
# Validated before the first mutation. An earlier version of this block ran the
# same regexes on behalf of the client-publishing step but let a bad value
# through to the last step, by which time the packages, the venv, a real IPA
# keytab, the certificate and the live vhost were all in place. That step is
# gone (the client bundle is assembled in step 9b, served here by default or
# exported for another host to serve), and so is its half of these checks:
# nothing on this host reads DOMAIN any more.
if [ "$DRY_RUN" != 1 ]; then
    case "$IPA_SERVER" in
        *example.internal*|*EXAMPLE.INTERNAL*)
            die "IPA_SERVER is still the placeholder '$IPA_SERVER' in $SITE_ENV.
  Fill it in and re-run. Nothing has been changed." ;;
    esac

    ok_fqdn() { printf '%s\n' "$1" | grep -Eq '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'; }
    for _v in FQDN IPA_SERVER; do
        eval "_val=\${$_v}"
        ok_fqdn "$_val" || die "$_v=\"$_val\" is not a lowercase dotted FQDN.
  Nothing has been changed."
    done
    printf '%s\n' "$REALM" | grep -Eq '^[A-Z0-9]([A-Z0-9-]*[A-Z0-9])?(\.[A-Z0-9]([A-Z0-9-]*[A-Z0-9])?)+$' \
        || die "REALM=\"$REALM\" is not an uppercase Kerberos realm.
  Nothing has been changed."
fi

python3 - <<'PY' || die "python3 >= 3.11 is required"
import sys
sys.exit(0 if sys.version_info >= (3, 11) else 1)
PY
say "PASS python3 >= 3.11"

# --------------------------------------------------------------------------
# 1. PACKAGES
# --------------------------------------------------------------------------
step "1. packages"

if [ "$PKGMGR" = apt ]; then
    PKGS="nginx certbot python3-certbot-nginx python3-venv python3-gssapi krb5-user freeipa-client"
    # A stale package list is why the first build failed with "Unable to locate
    # package freeipa-client". An update failure is tolerated; a missing package
    # is not: the assertion loop below is the real gate.
    if [ "$DRY_RUN" = 1 ]; then
        say "  would install: $PKGS"
    else
        DEBIAN_FRONTEND=noninteractive apt-get update -qq \
            || warn "apt-get update failed, continuing with cached lists"
        # shellcheck disable=SC2086
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PKGS
    fi
else
    PKGS="nginx certbot python3-certbot-nginx python3-gssapi krb5-workstation"
    if [ "$DRY_RUN" = 1 ]; then
        say "  would install: $PKGS ipa-client"
    else
        # shellcheck disable=SC2086
        dnf -y install $PKGS
        dnf -y install ipa-client || dnf -y install freeipa-client
    fi
fi

if [ "$DRY_RUN" != 1 ]; then
    missing=""
    for b in nginx certbot python3 klist; do
        command -v "$b" >/dev/null 2>&1 || missing="$missing $b"
    done
    [ -n "$missing" ] && die "packages installed but these binaries are still missing:$missing"
    # The system interpreter must have gssapi, because the venv borrows it via
    # --system-site-packages. gssapi is an OS package, not a pip package here.
    /usr/bin/python3 -c 'import gssapi' >/dev/null 2>&1 \
        || die "/usr/bin/python3 cannot import gssapi. Install python3-gssapi (apt) or python3-gssapi (dnf)."
    say "PASS all required binaries present, system python3 imports gssapi"
fi

# --------------------------------------------------------------------------
# 2. SERVICE ACCOUNT
#    getent, never `id`: on an IPA-enrolled host `id mcp` resolves through SSSD
#    and would report an IPA account that has no local presence.
# --------------------------------------------------------------------------
step "2. service account $SVCUSER:$SVCGROUP"

if getent passwd "$SVCUSER" >/dev/null 2>&1; then
    say "PASS user $SVCUSER already exists (left untouched)"
else
    nologin="$(command -v nologin || echo /usr/sbin/nologin)"
    getent group "$SVCGROUP" >/dev/null 2>&1 || run groupadd --system "$SVCGROUP"
    run useradd --system --gid "$SVCGROUP" --home-dir /nonexistent \
                --no-create-home --shell "$nologin" "$SVCUSER"
    say "created $SVCUSER:$SVCGROUP"
fi
if [ "$DRY_RUN" != 1 ]; then
    # Both are asserted, because --user and --group are independent: a run can
    # find the group already present and still have failed to create the user,
    # and that surfaces several steps later as a keytab permission error that
    # points at the wrong thing entirely.
    getent group  "$SVCGROUP" >/dev/null 2>&1 || die "group $SVCGROUP does not exist after account setup"
    getent passwd "$SVCUSER"  >/dev/null 2>&1 || die "user $SVCUSER does not exist after account setup.
  The unit declares User=$SVCUSER and will fail with
  'Failed to determine user credentials: No such process'."
fi

# --------------------------------------------------------------------------
# 3. VENV
#    --system-site-packages is required: python3-gssapi is an OS package (it
#    arrives with ipa-client) while mcp and uvicorn are pip-only, so an
#    isolated venv produces a server that starts and then fails every SPNEGO
#    handshake with a missing-credentials error that looks like a keytab problem.
# --------------------------------------------------------------------------
step "3. venv $MCP_VENV"

if [ -x "$MCP_VENV/bin/python" ]; then
    say "venv already present"
else
    run python3 -m venv --system-site-packages "$MCP_VENV"
    say "created venv"
fi

if [ "$DRY_RUN" != 1 ]; then
    grep -qi '^include-system-site-packages *= *true' "$MCP_VENV/pyvenv.cfg" 2>/dev/null \
        || die "$MCP_VENV was built WITHOUT --system-site-packages, so 'import gssapi' will fail.
  Remove $MCP_VENV and re-run this installer."

    if [ -f "$SERVERDIR/requirements.lock.txt" ]; then
        REQ="$SERVERDIR/requirements.lock.txt"
    else
        REQ="$SERVERDIR/requirements.txt"
        warn "requirements.lock.txt not found, falling back to unpinned $REQ"
    fi
    if [ -n "$WHEELHOUSE" ]; then
        "$MCP_VENV/bin/pip" install --quiet --no-index --find-links "$WHEELHOUSE" -r "$REQ"
    else
        "$MCP_VENV/bin/pip" install --quiet -r "$REQ"
    fi

    # Gate before anything is enabled; the die text maps each missing import.
    "$MCP_VENV/bin/python" -c 'import gssapi, mcp, uvicorn' >/dev/null 2>&1 || die \
"$MCP_VENV/bin/python cannot import gssapi, mcp and uvicorn together.
  gssapi missing  -> the venv was built without --system-site-packages: rm -rf $MCP_VENV and re-run.
  mcp/uvicorn missing -> pip install failed: check $REQ and network or --wheelhouse access."
    say "PASS venv imports gssapi, mcp, uvicorn"
fi

# --------------------------------------------------------------------------
# 4. CODE
#    Root-owned and not writable by the service user: ProtectSystem=strict keeps
#    the code read-only at runtime and this keeps it read-only at rest too.
# --------------------------------------------------------------------------
step "4. server code -> $CODEDIR"

run install -d -m 0755 -o root -g root "$CODEDIR"

# The directory converges on the repo's file set rather than only accumulating.
#
# This step used to only ever add files, so a module dropped from the repo sat
# in the runtime code directory of the service forever. authz_editor.py is the
# one that matters: the unit assertion in step 6 exists specifically to keep
# the policy editor switched off, and leaving its module lying in $CODEDIR
# across every future install undermines the reason that assertion is there.
#
# Nothing this script did not install is ever removed. The previous run's file
# list is kept in $STAMPDIR/codedir.manifest and only names appearing in that
# list may be deleted, so an operator's own file in $CODEDIR survives untouched
# and a host with no manifest yet (every host, on the first run after this
# change) deletes nothing at all.
CODE_MANIFEST="$STAMPDIR/codedir.manifest"
: > "$RENDER/codedir.manifest"
_n=0
for f in "$SERVERDIR"/*.py; do
    [ -f "$f" ] || continue
    run install -m 0644 -o root -g root "$f" "$CODEDIR/"
    basename -- "$f" >> "$RENDER/codedir.manifest"
    _n=$((_n + 1))
done
say "installed $_n python files"

if [ "$DRY_RUN" != 1 ]; then
    if [ -f "$CODE_MANIFEST" ]; then
        while IFS= read -r _old; do
            [ -n "$_old" ] || continue
            # still shipped by this repo? then it was just reinstalled
            grep -qxF -- "$_old" "$RENDER/codedir.manifest" && continue
            [ -f "$CODEDIR/$_old" ] || continue
            rm -f "$CODEDIR/$_old"
            say "removed $CODEDIR/$_old (installed by an earlier run, no longer in the repo)"
        done < "$CODE_MANIFEST"
    else
        say "no previous code manifest at $CODE_MANIFEST - nothing is removed on this run"
    fi
    install -d -m 0700 -o root -g root "$STAMPDIR"
    install -m 0600 -o root -g root "$RENDER/codedir.manifest" "$CODE_MANIFEST"
fi

# --------------------------------------------------------------------------
# 5. IPA SERVICE + KEYTAB   (this is the step that caused the first-boot outage)
# --------------------------------------------------------------------------
step "5. keytab for $MCP_SPN_KRB"

run install -d -o root -g "$SVCGROUP" -m 0750 "$CONFDIR"

need_keytab=1
if [ -f "$KEYTAB" ] && klist -k "$KEYTAB" 2>/dev/null | grep -qF "$MCP_SPN_KRB"; then
    if [ "$ROTATE_KEYTAB" = 1 ]; then
        warn "--rotate-keytab: re-retrieving will BUMP THE KVNO. Every ticket already issued
         against the current key stops validating and mcp-server must be restarted."
    else
        # Blind re-retrieval is the opposite of idempotent: it invalidates the key
        # the running acceptor is using. Existing and correct means done.
        say "PASS keytab already holds $MCP_SPN_KRB (kvno $(klist -k "$KEYTAB" 2>/dev/null | grep -F "$MCP_SPN_KRB" | awk '{print $1}' | head -1)) - not touching it"
        need_keytab=0
    fi
fi

if [ "$need_keytab" = 1 ] && [ "$DRY_RUN" != 1 ]; then
    # A private ccache, so we never clobber /tmp/krb5cc_0 or leak a host ticket.
    # cleanup() kdestroys it and removes the directory on every exit path.
    KRB5CCNAME="FILE:$CCDIR/ccache"; export KRB5CCNAME

    kinit -k -t /etc/krb5.keytab "host/$FQDN" \
        || die "kinit as host/$FQDN failed. Check the clock skew against $IPA_SERVER and /etc/krb5.keytab."

    if ipa service-show "HTTP/$FQDN" >/dev/null 2>&1; then
        say "IPA service HTTP/$FQDN exists"
    elif [ "$CREATE_IPA_SERVICE" = 1 ]; then
        # No --force on purpose: without a DNS A record this must fail loudly
        # rather than mint a principal for a name nothing resolves.
        ipa service-add "HTTP/$FQDN" \
            || die "ipa service-add HTTP/$FQDN failed. It needs an admin ticket (kinit admin) and a DNS record for $FQDN."
    else
        die "IPA service HTTP/$FQDN does not exist. An IPA admin must run:
    ipa service-add HTTP/$FQDN
  Leave both delegation checkboxes OFF. Then re-run this installer.
  (Or re-run with --create-ipa-service while holding an admin ticket.)"
    fi

    ipa service-show "HTTP/$FQDN" 2>/dev/null | grep -qi "Managed by:.*$FQDN" \
        || die "HTTP/$FQDN is not managed by host $FQDN, so this host may not retrieve its keytab.
  An IPA admin must run:  ipa service-add-host HTTP/$FQDN --hosts=$FQDN"

    # Retrieve into a private temp file and install atomically, so an interrupted
    # fetch never leaves a truncated or world-readable keytab in place.
    # umask is saved and restored: leaving 077 set would silently change the mode
    # of everything certbot and nginx create later in this same run.
    OLD_UMASK="$(umask)"
    umask 077
    KTTMP="$CCDIR/krb5.keytab"
    ipa-getkeytab -s "$IPA_SERVER" -p "HTTP/$FQDN" -k "$KTTMP" \
        || die "ipa-getkeytab failed for HTTP/$FQDN against $IPA_SERVER"
    install -m 0600 -o root -g root "$KTTMP" "$KEYTAB"
    umask "$OLD_UMASK"
    say "retrieved keytab for $MCP_SPN_KRB"
fi

# 0750 dir + 0640 keytab, root:<svcgroup>. The service user MUST be able to read
# the keytab. A 0750 root:root directory is what produced the opaque
# 'MissingCredentialsError ... Minor (13): Permission denied' on the first build.
if [ "$DRY_RUN" != 1 ] && [ -f "$KEYTAB" ]; then
    chown "root:$SVCGROUP" "$CONFDIR" "$KEYTAB"
    chmod 0750 "$CONFDIR"
    chmod 0640 "$KEYTAB"
    say "keytab permissions: 0640 root:$SVCGROUP, dir 0750"
fi

# Hard gate. runuser works despite the nologin shell, and klist -k exits 0 on a
# readable but empty keytab, so the SPN grep is required.
if [ "$DRY_RUN" != 1 ]; then
    if runuser -u "$SVCUSER" -- klist -k "$KEYTAB" 2>/dev/null | grep -qF "$MCP_SPN_KRB"; then
        say "PASS $SVCUSER can read $MCP_SPN_KRB from $KEYTAB"
    else
        die "$SVCUSER cannot read $MCP_SPN_KRB from $KEYTAB.
  Started this way the server fails every handshake with the opaque
  'MissingCredentialsError ... Major (458752) / Minor (13): Permission denied'.
  Remediation:
    chown root:$SVCGROUP $CONFDIR $KEYTAB
    chmod 0750 $CONFDIR ; chmod 0640 $KEYTAB"
    fi
fi

# --------------------------------------------------------------------------
# 6. RENDER THE UNIT
#    sed substitutes values only. The comments in mcp-server.service record the
#    outage history and must survive verbatim.
# --------------------------------------------------------------------------
# nginx's group, needed by the unit's ExecStartPost to tighten the proxy socket.
# Discovered at runtime (www-data on Debian and Ubuntu, nginx on RHEL):
# hardcoding either produces a socket the proxy cannot open, and a 502 on every
# request from an install that otherwise reports success.
NGINX_GROUP="$(ps -o group= -C nginx 2>/dev/null | grep -v '^root$' | head -1)"
[ -n "$NGINX_GROUP" ] || NGINX_GROUP=www-data
getent group "$NGINX_GROUP" >/dev/null 2>&1 || \
    die "cannot determine nginx group (guessed $NGINX_GROUP, which does not exist)."

step "6. systemd unit"

sed -e "s/mcp\.example\.internal/$FQDN/g" \
    -e "s/EXAMPLE\.INTERNAL/$REALM/g" \
    -e "s#^ExecStart=.*#ExecStart=$MCP_VENV/bin/python $CODEDIR/mcp_server.py#" \
    -e "s/^User=.*/User=$SVCUSER/" \
    -e "s/^Group=.*/Group=$SVCGROUP/" \
    -e "s/{{NGINX_GROUP}}/$NGINX_GROUP/g" \
    "$INSTALLDIR/mcp-server.service" > "$RENDER/mcp-server.service"

# On-behalf-of forwarding, SECURITY.md [D1]. The unit ships it commented out,
# so uncommenting is what enabling looks like, and site.env is the one place a
# site says so. Only an explicit truthy value counts: an unset or empty
# MCP_DELEGATION leaves the commented line exactly as shipped, the off state.
#
# Announced loudly rather than applied quietly, because this narrows [C2]: the
# keytab stops being receive-only and becomes usable for outbound
# authentication. An operator who set this without reading [D1] should find
# out here at install time rather than from an audit later.
case "${MCP_DELEGATION:-}" in
    1|true|TRUE|yes|YES|on|ON)
        sed -i 's/^# *Environment=MCP_DELEGATION=1/Environment=MCP_DELEGATION=1/' \
            "$RENDER/mcp-server.service"
        grep -q '^Environment=MCP_DELEGATION=1' "$RENDER/mcp-server.service" \
            || die "MCP_DELEGATION is set in site.env but the unit template has no
  '# Environment=MCP_DELEGATION=1' line to uncomment. Refusing to install a unit
  that would silently run WITHOUT forwarding while site.env says it is on."
        warn "MCP_DELEGATION is ON. The acceptor credential will be acquired usage='both',
         so the keytab becomes usable for OUTBOUND authentication and not only
         inbound. This narrows [C2] and changes what a stolen keytab is worth
         under [K1]. It additionally requires a FreeIPA servicedelegationrule and
         callers holding FORWARDABLE tickets; without both, forwarding fails
         closed with KDC_ERR_BADOPTION and tools that forward will refuse."
        ;;
    ''|0|false|FALSE|no|NO|off|OFF)
        # Shipped state: the line stays commented and the acceptor stays
        # receive-only. Targets without the switch would look enabled in site.env
        # while forwarding silently never happened, so refuse rather than ignore.
        [ -n "${MCP_DELEGATION_TARGETS:-}" ] && die "MCP_DELEGATION_TARGETS names a downstream target but MCP_DELEGATION is off.
  That combination reads as 'forwarding is configured' while nothing forwards.
  Set MCP_DELEGATION=1 in $SITE_ENV, or clear MCP_DELEGATION_TARGETS."
        : ;;
    *)
        die "MCP_DELEGATION='$MCP_DELEGATION' is not a recognised boolean.
  Refusing to guess: an unrecognised value here would silently mean OFF, and a
  site that believes forwarding is on would attribute downstream actions to the
  wrong identity. Use 1 or empty." ;;
esac

# Render MCP_DELEGATION_TARGETS, and validate it here rather than trusting the
# server to reject it at import. A bad value caught at install time is a message
# on this terminal; caught at import it is a service that will not start, found
# later by whoever is on call. Same grammar as delegation._targets_from_env().
if [ -n "${MCP_DELEGATION_TARGETS:-}" ]; then
    # Split on commas without a pipe: `die` inside a `while` fed by a pipeline
    # runs in a subshell, so it would kill only the subshell and the install
    # would carry on past a target it had just rejected.
    _rest="$MCP_DELEGATION_TARGETS"
    _seen=' '
    while [ -n "$_rest" ]; do
        case "$_rest" in
            *,*) _ent="${_rest%%,*}"; _rest="${_rest#*,}" ;;
            *)   _ent="$_rest";       _rest= ;;
        esac
        _ent="$(printf '%s' "$_ent" | tr -d '[:space:]')"
        [ -n "$_ent" ] || continue
        printf '%s' "$_ent" \
            | grep -Eq '^[a-z][a-z0-9_]{0,63}=[A-Za-z0-9_-]{1,32}@[a-z0-9.-]{3,253}$' \
            || die "MCP_DELEGATION_TARGETS entry '$_ent' is malformed.
  Want tool=service@fqdn, e.g. trigger_build=HTTP@ci.example.internal.
  FQDNs only: a short name could be widened by whatever the resolver decides.
  One target per tool, and a comma separates ENTRIES, never two targets."
        _tool="${_ent%%=*}"
        # Two rows for one tool has no safe answer: target_for() refuses an
        # ambiguous tool at runtime, so every call would fail closed while
        # site.env looked configured.
        case "$_seen" in
            *" $_tool "*) die "MCP_DELEGATION_TARGETS lists '$_tool' more than once.
  A tool gets exactly one downstream target. Two would mean something chooses at
  runtime, and the only inputs available then come from the caller." ;;
        esac
        _seen="$_seen$_tool "
        # A target for a tool that cannot forward is a live grant sitting unused,
        # waiting for some future function to be given that name. Refuse it while
        # it is still a typo rather than an inheritance.
        # Look in the site tools file too. A deployment's own forwarding tools
        # live there rather than in mcp_server.py, and checking only the shipped
        # file would refuse every real target a site ever adds.
        # Two shapes count as forwarding, because both are real. The direct one is
        # forward_header(ctx, 'tool') written out in the tool body. The indirect one
        # is a helper that takes the tool name and forwards on its behalf:
        #
        #     def _get(ctx, tool, path): ... forward_header(ctx, tool) ...
        #     _get(ctx, 'list_docs', ...)
        #
        # which is how any file with more than a couple of forwarding tools ends up
        # written, since a fresh Negotiate header is needed per request. Matching
        # only the literal made this check refuse every such tool as "dead config",
        # so a site using the helper pattern could not install at all: list_docs,
        # read_doc and the pull-request tools were all rejected while working
        # perfectly at runtime.
        #
        # The indirect test still catches what this check is for. A typo'd or
        # retired name appears nowhere in the file, so it fails both arms. What it
        # gives up is detecting a tool that is named in the file but never actually
        # forwards, which is a far smaller error than refusing to install a correct
        # configuration.
        _found=0
        for _pyf in "$CODEDIR/mcp_server.py" "${MCP_SITE_TOOLS:-}"; do
            [ -n "$_pyf" ] && [ -f "$_pyf" ] || continue
            if grep -q "forward_header(ctx, '$_tool')" "$_pyf"; then _found=1; break; fi
            if grep -q 'forward_header(' "$_pyf" \
               && grep -qE "['\"]$_tool['\"]" "$_pyf"; then _found=1; break; fi
        done
        [ "$_found" = 1 ] \
            || die "MCP_DELEGATION_TARGETS grants '$_tool' a downstream target, but no
  tool by that name forwards in mcp_server.py${MCP_SITE_TOOLS:+ or $MCP_SITE_TOOLS}: the name
  appears in neither a forward_header(ctx, '$_tool') call nor anywhere in a file
  that forwards at all. Either the name is a typo, or the grant is dead config.
  Refusing to install an unused grant."
    done
    # '|' as the sed delimiter, not '#': the pattern starts with a literal '#'
    # (the commented line being filled in), which would close the expression.
    sed -i "s|^# *Environment=MCP_DELEGATION_TARGETS=.*|Environment=MCP_DELEGATION_TARGETS=$MCP_DELEGATION_TARGETS|" \
        "$RENDER/mcp-server.service"
    grep -q '^Environment=MCP_DELEGATION_TARGETS=' "$RENDER/mcp-server.service" \
        || die "MCP_DELEGATION_TARGETS is set but the unit template has no
  '# Environment=MCP_DELEGATION_TARGETS=' line to fill in. Refusing to install a
  unit whose forwarding tools would all fail closed while site.env says they work."
    say "delegation targets: $MCP_DELEGATION_TARGETS"
fi

# A deployment's own tools. The file is not carried by this repository and not
# deployed by this script: it names internal hosts, and it must live outside
# $CODEDIR because the step above converges that directory on the repo's file
# set and would delete it.
#
# Checked here rather than left to the server, for the same reason as the
# targets: a missing file caught now is a line on this terminal, caught at
# import it is a unit that will not start.
if [ -n "${MCP_SITE_TOOLS:-}" ]; then
    case "$MCP_SITE_TOOLS" in
        /*) ;;
        *) die "MCP_SITE_TOOLS must be an absolute path, got '$MCP_SITE_TOOLS'." ;;
    esac
    case "$MCP_SITE_TOOLS" in
        "$CODEDIR"/*) die "MCP_SITE_TOOLS points inside $CODEDIR, which this script
  converges on the repository's file set. The file would be deleted on the next
  install. Put it somewhere this script does not manage, e.g. /etc/mcp-server/." ;;
    esac
    [ -f "$MCP_SITE_TOOLS" ] || die "MCP_SITE_TOOLS names $MCP_SITE_TOOLS, which does not exist.
  Refusing to install a unit that would fail at startup."
    # It becomes code inside the service, so anything that can write it can run
    # as the service, which holds the keytab. Same standard as $CODEDIR.
    _st_owner="$(stat -c '%U' "$MCP_SITE_TOOLS")"
    [ "$_st_owner" = root ] || die "MCP_SITE_TOOLS ($MCP_SITE_TOOLS) is owned by
  '$_st_owner', not root. It is imported by the service, so a non-root owner means
  that account can execute code as the service. Install it root-owned 0644."
    case "$(stat -c '%a' "$MCP_SITE_TOOLS")" in
        *[2367])
            die "MCP_SITE_TOOLS ($MCP_SITE_TOOLS) is group- or world-writable.
  It is imported by the service; make it 0644 root-owned." ;;
    esac
    # /usr/bin/python3, not the venv: preflight already proved this one exists
    # and is >= 3.11, and a syntax check needs no third-party imports.
    /usr/bin/python3 -c "import ast,io,sys; ast.parse(io.open(sys.argv[1],encoding='utf-8').read())" \
        "$MCP_SITE_TOOLS" 2>/dev/null \
        || die "MCP_SITE_TOOLS ($MCP_SITE_TOOLS) is not valid Python.
  It would stop the service at startup. Fix it before installing."
    sed -i "s|^# *Environment=MCP_SITE_TOOLS=.*|Environment=MCP_SITE_TOOLS=$MCP_SITE_TOOLS|" \
        "$RENDER/mcp-server.service"
    grep -q '^Environment=MCP_SITE_TOOLS=' "$RENDER/mcp-server.service" \
        || die "MCP_SITE_TOOLS is set but the unit template has no
  '# Environment=MCP_SITE_TOOLS=' line to fill in."
    say "site tools: $MCP_SITE_TOOLS"
fi

# --- policy editor ----------------------------------------------------------
# The switch is --enable-authz-editor and deliberately NOT a site.env key. The
# editor is an authenticated write surface over tool authorization: whoever can
# reach it can widen who may call what. Keeping the switch in the invocation
# means a human asked for it, while automation that only supplies a parameter
# file cannot turn it on. That is the same rule the old assertion enforced by
# forbidding the line outright; the difference is that the state is now
# reachable from source instead of only by hand-editing the unit afterwards,
# which is how the live host ended up unreproducible.
#
# The three values below are inert without the switch, so they are ordinary
# site.env keys.
MCP_POLICY_ADMINS="${MCP_POLICY_ADMINS:-}"
MCP_POLICY_FILE="${MCP_POLICY_FILE:-/var/lib/mcp-server/tool-groups.json}"
MCP_PUBLIC_ORIGIN="${MCP_PUBLIC_ORIGIN:-https://$FQDN}"

case "${MCP_AUTHZ_EDITOR:-}" in
    ''|0|false|FALSE|no|NO|off|OFF) : ;;
    *) die "MCP_AUTHZ_EDITOR is set in $SITE_ENV, and it is not settable there.
  The policy editor is an authenticated write surface over tool authorization, so
  enabling it is a decision the person running the installer makes, not one a
  parameter file makes on their behalf. Remove it from site.env and pass
  --enable-authz-editor instead." ;;
esac

if [ "$ENABLE_AUTHZ_EDITOR" = 1 ]; then
    [ -n "$MCP_POLICY_ADMINS" ] || die "--enable-authz-editor needs MCP_POLICY_ADMINS in $SITE_ENV.
  An editor with no admins is a page that authenticates everyone and authorises
  nobody, and the only way to find that out is to open it."
    # Full principals only. A bare username would silently never match, so the
    # editor would authenticate the right person and refuse them.
    _rest="$MCP_POLICY_ADMINS"
    while [ -n "$_rest" ]; do
        case "$_rest" in
            *,*) _adm="${_rest%%,*}"; _rest="${_rest#*,}" ;;
            *)   _adm="$_rest";       _rest= ;;
        esac
        _adm="$(printf '%s' "$_adm" | tr -d '[:space:]')"
        [ -n "$_adm" ] || continue
        printf '%s' "$_adm" | grep -Eq '^[A-Za-z0-9._-]{1,64}@[A-Z0-9.-]{3,253}$' \
            || die "MCP_POLICY_ADMINS entry '$_adm' is not a Kerberos principal.
  Want user@REALM with the realm UPPERCASE, e.g. alice@$REALM."
        case "$_adm" in
            *@"$REALM") ;;
            *) die "MCP_POLICY_ADMINS entry '$_adm' is not in this realm ($REALM).
  The acceptor only ever sees principals from its own realm, so this could never
  match and the editor would refuse that person forever." ;;
        esac
    done

    sed -i 's/^# *Environment=MCP_AUTHZ_EDITOR=1/Environment=MCP_AUTHZ_EDITOR=1/' \
        "$RENDER/mcp-server.service"
    sed -i "s|^# *Environment=MCP_POLICY_ADMINS=.*|Environment=MCP_POLICY_ADMINS=$MCP_POLICY_ADMINS|" \
        "$RENDER/mcp-server.service"
    sed -i "s|^# *Environment=MCP_POLICY_FILE=.*|Environment=MCP_POLICY_FILE=$MCP_POLICY_FILE|" \
        "$RENDER/mcp-server.service"
    sed -i "s|^# *Environment=MCP_PUBLIC_ORIGIN=.*|Environment=MCP_PUBLIC_ORIGIN=$MCP_PUBLIC_ORIGIN|" \
        "$RENDER/mcp-server.service"
    # The policy file lives here, and ProtectSystem=strict makes everything else
    # read-only. Without the state directory the editor starts, authenticates,
    # and fails only when someone tries to save.
    sed -i 's/^# *StateDirectory=mcp-server$/StateDirectory=mcp-server/' \
        "$RENDER/mcp-server.service"
    sed -i 's/^# *StateDirectoryMode=0750$/StateDirectoryMode=0750/' \
        "$RENDER/mcp-server.service"

    for _k in MCP_AUTHZ_EDITOR MCP_POLICY_ADMINS MCP_POLICY_FILE MCP_PUBLIC_ORIGIN; do
        grep -q "^Environment=$_k=" "$RENDER/mcp-server.service" \
            || die "--enable-authz-editor was given but the unit template has no
  '# Environment=$_k=' line to fill in. Refusing to install a unit that would run
  without the editor while the operator asked for it."
    done
    grep -qx 'StateDirectory=mcp-server' "$RENDER/mcp-server.service" \
        || die "--enable-authz-editor was given but the unit template has no
  '# StateDirectory=mcp-server' line to uncomment; the editor could not save."

    warn "POLICY EDITOR IS ON at $MCP_PUBLIC_ORIGIN/admin/authz.
         It is an authenticated WRITE surface over tool authorization: anyone in
         MCP_POLICY_ADMINS can change which IPA groups may call which tool, and
         those changes take effect without a deploy. Admins: $MCP_POLICY_ADMINS"
    say "policy editor: on, admins=$MCP_POLICY_ADMINS, policy=$MCP_POLICY_FILE"
fi

assert_rendered() {
    f="$1"
    grep -q 'example\.internal' "$f"  && die "rendering left example.internal in $f"
    grep -q 'EXAMPLE\.INTERNAL' "$f"  && die "rendering left EXAMPLE.INTERNAL in $f"
    return 0
}
assert_rendered "$RENDER/mcp-server.service"
[ "$(grep -c '^ExecStart=' "$RENDER/mcp-server.service")" = 1 ] \
    || die "rendered unit must have exactly one ExecStart= line"
[ -x "$MCP_VENV/bin/python" ] || [ "$DRY_RUN" = 1 ] \
    || die "$MCP_VENV/bin/python is not executable but ExecStart points at it"
grep -q '^RuntimeDirectoryMode=0755' "$RENDER/mcp-server.service" \
    || die "rendered unit lost RuntimeDirectoryMode=0755; nginx cannot traverse /run/mcp-server without it"
# The acceptor finds its keytab only through this line. It used to live in a
# service.d drop-in that this installer wrote, so losing it from the template
# was survivable; inline, the template is the only source.
grep -qx "Environment=KRB5_KTNAME=$KEYTAB" "$RENDER/mcp-server.service" \
    || die "rendered unit has no 'Environment=KRB5_KTNAME=$KEYTAB'.
  Without it gssapi looks in the system default keytab and every handshake fails
  with 'MissingCredentialsError'. Check server/install/mcp-server.service."
# Automation must never be able to switch the policy editor on. The rule is
# unchanged; what changed is that there is now one legitimate way to reach the
# active state, --enable-authz-editor, which only a person invoking the installer
# can supply. Anything else that produces an active line, a stray template edit or
# a sed that matched too much, is still refused here.
if [ "$ENABLE_AUTHZ_EDITOR" != 1 ]; then
    grep -q '^Environment=MCP_AUTHZ_EDITOR' "$RENDER/mcp-server.service" \
        && die "rendered unit has an ACTIVE MCP_AUTHZ_EDITOR line but
  --enable-authz-editor was not given. The policy editor must never switch itself
  on. Check server/install/mcp-server.service for an uncommented line."
    grep -qx 'StateDirectory=mcp-server' "$RENDER/mcp-server.service" \
        && die "rendered unit has an ACTIVE StateDirectory but the policy editor is
  off; nothing else needs a writable state directory. Check the template."
fi
say "PASS rendered unit passes all assertions"

install_if_changed() {
    src="$1"; dst="$2"; stamp="$3"
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        say "unchanged: $dst"
        # Adopt the file as managed even though nothing was written. Without this
        # a host whose unit already matches the render never gets a stamp, and the
        # next template change then trips the "unmanaged file" abort for no reason.
        if [ -n "$stamp" ] && [ ! -f "$stamp" ]; then
            run install -d -m 0700 -o root -g root "$(dirname "$stamp")"
            run install -m 0600 -o root -g root "$src" "$stamp"
        fi
        return 1
    fi
    if [ -f "$dst" ] && [ -n "$stamp" ]; then
        # Distinguish "the template changed" from "somebody edited the live file".
        if [ -f "$stamp" ] && ! cmp -s "$stamp" "$dst" && [ "$FORCE_UNIT" != 1 ]; then
            say "--- local edits detected in $dst ---"
            diff -u "$stamp" "$dst" || true
            die "$dst has edits this installer did not make. Fold them into the repo template,
  or re-run with --force-unit to overwrite them."
        fi
        if [ ! -f "$stamp" ] && [ "$FORCE_UNIT" != 1 ]; then
            say "--- $dst exists but was not installed by this script ---"
            diff -u "$dst" "$src" || true
            die "refusing to clobber an unmanaged $dst. Re-run with --force-unit once you have
  confirmed the diff above is safe to lose."
        fi
    fi
    run install -m 0644 -o root -g root "$src" "$dst"
    [ -n "$stamp" ] && run install -d -m 0700 -o root -g root "$(dirname "$stamp")"
    [ -n "$stamp" ] && run install -m 0600 -o root -g root "$src" "$stamp"
    return 0
}

unit_changed=0
install_if_changed "$RENDER/mcp-server.service" "$UNIT" "$STAMPDIR/mcp-server.service" && unit_changed=1

if [ "$unit_changed" = 1 ] && [ "$DRY_RUN" != 1 ]; then
    systemctl daemon-reload
    systemd-analyze verify "$UNIT" || warn "systemd-analyze verify reported issues on $UNIT"
fi

# --------------------------------------------------------------------------
# 7. RENDER THE VHOST (placed in step 9, after the certificate exists)
# --------------------------------------------------------------------------
step "7. nginx vhost"

# Explicit {{TOKEN}} substitution rather than pattern matching on an example
# hostname. '#' is the sed delimiter for the two path tokens because both
# values contain '/'. The client location is a block rather than a single
# value, built here and spliced in at the marker. With --no-serve-client the
# marker becomes nothing at all, and the rendered vhost is byte-identical to a
# server that never had the feature: no empty location, no commented stub.
CLIENT_BLOCK=""
if [ "$SERVE_CLIENT" = yes ]; then
    # 'root', not 'alias'. With alias, a location prefix that does not exactly
    # match the trailing slash lets a crafted URI escape the docroot. root just
    # appends the URI to the parent, so the last element of $CLIENT_ROOT must
    # equal the $CLIENT_PATH element; that is asserted after rendering.
    #
    # index index.html serves the provisioning page at the path itself; the
    # client scripts and app.js/config.js sit alongside it. default_type
    # text/plain is for the extensionless scripts (setup.sh, install-bridge.sh, the
    # .ps1/.py); index.html and app.js get their real types from mime.types,
    # which is included at the http level and takes precedence.
    CLIENT_PARENT="$(dirname "$CLIENT_ROOT")"
    CLIENT_BLOCK="location ^~ $CLIENT_PATH {
        root $CLIENT_PARENT;
        index index.html;
        autoindex off;
        default_type text/plain;
        add_header Cache-Control \"no-store\" always;
    }"
fi

sed -e "s/{{MCP_FQDN}}/$FQDN/g" \
    -e "s#{{CERTDIR}}#$CERTDIR#g" \
    -e "s#{{WEBROOT}}#$WEBROOT#g" \
    "$INSTALLDIR/nginx-mcp.nginx" > "$RENDER/mcp.conf"

# Spliced with awk, not sed: the block is multi-line and contains the characters
# sed treats as delimiters and backreferences.
awk -v blk="$CLIENT_BLOCK" '{
    if (index($0, "{{CLIENT_LOCATION}}")) { if (blk != "") print "    " blk; next }
    print
}' "$RENDER/mcp.conf" > "$RENDER/mcp.conf.tmp" && mv "$RENDER/mcp.conf.tmp" "$RENDER/mcp.conf"

assert_rendered "$RENDER/mcp.conf"
assert_no_tokens "$RENDER/mcp.conf"
grep -q 'acme-challenge' "$RENDER/mcp.conf" \
    || die "the rendered vhost has no /.well-known/acme-challenge/ exemption.
  Without it the port-80 block 308-redirects the ACME challenge into the
  Kerberos-gated proxy, which answers 401, and the next renewal fails silently."

# The single most important assertion in this script. certbot is invoked with
# -w "$WEBROOT"; if the vhost serves the challenge from any other directory,
# issuance still succeeds through the temporary bootstrap vhost in step 8 and
# every unattended renewal 404s afterwards, expiring the certificate silently
# ninety days later. The two are proven to agree here, at install time.
grep -qF "location ^~ /.well-known/acme-challenge/ { root $WEBROOT; }" "$RENDER/mcp.conf" \
    || die "the rendered vhost does not serve the ACME challenge from \$WEBROOT ($WEBROOT),
  but certbot will be invoked with -w $WEBROOT. Issuance would succeed and every
  renewal would then 404. Check the {{WEBROOT}} token in server/install/nginx-mcp.nginx."
# The certificate directory is substituted too, so --cert-mode existing
# --cert-path and an MCP_CERT_NAME that differs from MCP_HOST both reach the
# vhost. Substituting only the hostname left ssl_certificate pointing at
# /etc/letsencrypt/live/<fqdn>/, a path nothing had written a certificate into.
grep -qF "ssl_certificate     $CERTDIR/fullchain.pem" "$RENDER/mcp.conf" \
    || die "the rendered vhost does not point ssl_certificate at $CERTDIR"
# The root+path invariant. nginx appends the whole URI to root, so
# root=$(dirname $CLIENT_ROOT) only lands inside $CLIENT_ROOT when the path
# element and the docroot's last element are the same word. --client-path /d/
# with --client-root /var/www/client would serve /var/www/d/, which does not
# exist, and every workstation would 404 with a vhost that looks correct.
if [ "$SERVE_CLIENT" = yes ]; then
    _cp_elem="$(printf '%s' "$CLIENT_PATH" | tr -d '/')"
    _cr_elem="$(basename "$CLIENT_ROOT")"
    [ "$_cp_elem" = "$_cr_elem" ] || die "--client-path '$CLIENT_PATH' and --client-root '$CLIENT_ROOT' disagree.
  nginx appends the URI to root, so the path element ('$_cp_elem') and the last
  element of the docroot ('$_cr_elem') must be the same word. Either use
  --client-path /$_cr_elem/ or --client-root $(dirname "$CLIENT_ROOT")/$_cp_elem."
    grep -qF "location ^~ $CLIENT_PATH {" "$RENDER/mcp.conf"         || die "the rendered vhost has no client location for $CLIENT_PATH"
    say "PASS client bundle will be served at https://$FQDN$CLIENT_PATH from $CLIENT_ROOT"
fi

say "PASS rendered vhost keeps the ACME challenge exemption, serves it from $WEBROOT,"
say "     and reads its certificate from $CERTDIR"

if [ -d /etc/nginx/sites-available ]; then
    VHOST_AVAIL="/etc/nginx/sites-available/mcp"
    VHOST_LINK="/etc/nginx/sites-enabled/mcp"
else
    VHOST_AVAIL="/etc/nginx/conf.d/mcp.conf"
    VHOST_LINK=""
fi
say "vhost layout: $VHOST_AVAIL${VHOST_LINK:+ -> $VHOST_LINK}"

# The .bak is taken at most once per run, on the first call, and it therefore
# always holds the configuration this run found on disk.
#
# This used to snapshot on every call. Step 8 calls place_vhost with the
# HTTP-only bootstrap vhost, so on a re-install over a working host the second
# call overwrote the operator's real vhost backup with the bootstrap one. If
# step 9's `nginx -t` then failed, the rollback restored the bootstrap config,
# leaving `location / { return 404; }` on :80 with no TLS listener at all, and
# printed "the previous configuration was restored". That message was false,
# and a false recovery message is worse than no recovery at all.
VHOST_BACKED_UP=0
place_vhost() {
    src="$1"
    if [ "$VHOST_BACKED_UP" = 0 ] && [ -f "$VHOST_AVAIL" ] && ! cmp -s "$src" "$VHOST_AVAIL"; then
        run cp -p "$VHOST_AVAIL" "$VHOST_AVAIL.bak"
        say "saved the pre-existing vhost to $VHOST_AVAIL.bak"
    fi
    # Set unconditionally: after the first call the file on disk is ours, so
    # there is nothing left worth backing up even if that first call skipped it.
    VHOST_BACKED_UP=1
    run install -m 0644 -o root -g root "$src" "$VHOST_AVAIL"
    # Arm the rollback. From this line until step 9 disarms it, both die_vhost
    # and the INT/TERM/HUP handler will put back what this run found. Not armed
    # under --dry-run, where run() wrote nothing and there is nothing to undo.
    [ "$DRY_RUN" = 1 ] || VHOST_ROLLBACK_ARMED=1
    # ln -sfn, not -sf: with an existing symlink, -sf creates a link inside the
    # target directory instead of replacing it.
    [ -n "$VHOST_LINK" ] && run ln -sfn "$VHOST_AVAIL" "$VHOST_LINK"
    return 0
}

# The counterpart to place_vhost, reachable from every failure path that opens
# after the first place_vhost call, not only from step 9's `nginx -t`.
#
# Step 8 installs the HTTP-only bootstrap vhost and reloads nginx before the
# two checks most likely to fail on a real site: the ACME directory probe and
# certbot itself. Both of those once die()d without restoring anything and
# without mentioning that the live site had just been replaced by
# `location / { return 404; }` on :80 with no :443 listener at all. A host
# that was serving was left down while the printed remediation pointed at the
# IPA server. The three-outcome rollback existed only in step 9, the shorter
# and less likely window.
#
# RESTORED is set to a message naming which of the three outcomes actually
# occurred.
#
# Runs exactly once. The rollback is gated on VHOST_ROLLBACK_ARMED rather than
# on VHOST_BACKED_UP, so the die paths, the two warn paths in steps 8 and 9,
# and the signal handler can all call it freely: the first call that has
# something to undo does the work and disarms, every later call is a no-op
# that leaves $RESTORED naming what actually happened instead of overwriting
# it with a fresh, and by then untrue, "nothing needed restoring". Step 9
# disarms it on success, so a vhost is never rolled back after it has been
# accepted.
restore_vhost() {
    [ "$DRY_RUN" = 1 ] && return 0
    [ "$VHOST_ROLLBACK_ARMED" = 1 ] || return 0
    VHOST_ROLLBACK_ARMED=0
    if [ -f "$VHOST_AVAIL.bak" ]; then
        cp -p "$VHOST_AVAIL.bak" "$VHOST_AVAIL"
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx >/dev/null 2>&1 || true
            RESTORED="the configuration found before this run was restored from $VHOST_AVAIL.bak and nginx was reloaded"
        else
            rm -f "$VHOST_AVAIL"
            [ -n "$VHOST_LINK" ] && rm -f "$VHOST_LINK"
            RESTORED="the pre-run configuration ALSO failed nginx -t, so the vhost was removed entirely.
  It is still on disk at $VHOST_AVAIL.bak"
        fi
    else
        rm -f "$VHOST_AVAIL"
        [ -n "$VHOST_LINK" ] && rm -f "$VHOST_LINK"
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx >/dev/null 2>&1 || true
        fi
        RESTORED="there was no pre-existing vhost, so the one this run installed was removed and nothing was left behind"
    fi
    return 0
}

# die(), but roll the vhost back first and append what the rollback did. Every
# die between the bootstrap vhost going live and the full vhost being accepted
# goes through this.
die_vhost() {
    restore_vhost
    die "$*
  $RESTORED"
}

# Remove the distro default site only while it is still the untouched symlink.
# sites-available/default is never touched, so the change is reversible.
if [ -L /etc/nginx/sites-enabled/default ]; then
    run rm -f /etc/nginx/sites-enabled/default
    say "removed the default site symlink (sites-available/default left in place)"
elif [ -e /etc/nginx/sites-enabled/default ]; then
    warn "/etc/nginx/sites-enabled/default is a real file, not the distro symlink - leaving it alone.
         If it declares default_server on :443 it will shadow this vhost."
fi

run install -d -m 0755 -o root -g root "$WEBROOT"
run install -d -m 0755 -o root -g root "$WEBROOT/.well-known"
run install -d -m 0755 -o root -g root "$WEBROOT/.well-known/acme-challenge"

# A static probe file, dropped by the installer so verify.sh can assert a
# real 200 instead of accepting 404.
#
# verify.sh mutates nothing, so it cannot plant this itself, and without
# it a 404 is indistinguishable between "nginx served this location and the file
# simply is not there" (correct) and "nginx is serving the challenge from a
# different root than certbot writes into" (silent renewal failure). Only the
# installer knows $WEBROOT is the same value it passes to `certbot -w`, so only
# the installer can leave evidence of it.
#
# Contents are a fixed non-secret marker. This is the http-01 challenge
# directory: it is world-readable by design and is the one path on this host that
# is deliberately reachable unauthenticated over plaintext. Nothing site-specific
# goes in it.
PROBE_FILE="$WEBROOT/.well-known/acme-challenge/verify-install-probe"
if [ "$DRY_RUN" = 1 ]; then
    say "  would write the ACME webroot probe: $PROBE_FILE"
else
    printf 'mcp-verify-install-probe\n' > "$RENDER/probe"
    install -m 0644 -o root -g root "$RENDER/probe" "$PROBE_FILE"
    say "ACME webroot probe written: $PROBE_FILE"
fi

# --------------------------------------------------------------------------
# 8. CERTIFICATE, before the TLS vhost goes live.
#    Chicken and egg: nginx-mcp.nginx names ssl_certificate paths and nginx
#    refuses to start when they do not exist, so an HTTP-only vhost carries the
#    ACME challenge first.
# --------------------------------------------------------------------------
step "8. certificate ($CERT_MODE)"

have_cert=0
[ -f "$CERTDIR/fullchain.pem" ] && [ -f "$CERTDIR/privkey.pem" ] && have_cert=1

if [ "$have_cert" = 1 ]; then
    say "PASS certificate already present at $CERTDIR"
elif [ "$CERT_MODE" = existing ]; then
    die "--cert-mode existing but $CERTDIR/fullchain.pem or privkey.pem is missing"
elif [ "$CERT_MODE" = none ]; then
    warn "--cert-mode none: no certificate at $CERTDIR. The TLS vhost is NOT being enabled.
         Install fullchain.pem and privkey.pem there, then re-run with --cert-mode existing."
elif [ "$DRY_RUN" = 1 ]; then
    say "  would issue a certificate for $FQDN via $ACME_DIRECTORY"
else
    [ -n "$ACME_DIRECTORY" ] || die "--cert-mode acme needs ACME_DIRECTORY (site.env) or --acme-directory"

    # Phase 1: HTTP-only vhost so the challenge can be served with no certificate.
    cat > "$RENDER/mcp-bootstrap.conf" <<BOOT
# Temporary HTTP-only vhost written by run.sh so certbot can complete
# the http-01 challenge before any certificate exists. Replaced by the full
# hardened vhost in step 9 of the same run.
server {
    listen 80;
    listen [::]:80;
    server_name $FQDN;
    location ^~ /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 404; }
}
BOOT
    place_vhost "$RENDER/mcp-bootstrap.conf"
    nginx -t || die_vhost "nginx -t failed on the bootstrap vhost"
    systemctl enable --quiet nginx 2>/dev/null || true
    systemctl reload nginx 2>/dev/null || systemctl start nginx

    # From here to the end of step 9 the live vhost is this run's 404-only
    # bootstrap, so every exit goes through die_vhost and puts back what was
    # found on disk.
    curl -fsS --max-time 10 -o /dev/null "$ACME_DIRECTORY" || die_vhost \
"cannot reach the ACME directory at $ACME_DIRECTORY.
  On the IPA server:   ipa-acme-manage enable
  On this host:        the IPA CA must be in the system trust store (ipa-client-install does this)."

    # The lineage check is only allowed to skip reissue when the files it claims
    # to manage are actually on disk. certbot keeps the renewal conf after the
    # live directory is removed, so "certbot tracks it" and "a certificate
    # exists" are different facts. Conflating them installed the TLS vhost
    # against files that did not exist and failed nginx -t.
    if [ -f "$CERTDIR/fullchain.pem" ] && [ -f "$CERTDIR/privkey.pem" ] \
       && certbot certificates --cert-name "$CERT_NAME" 2>/dev/null | grep -q "Certificate Name: $CERT_NAME"; then
        say "certbot already tracks lineage $CERT_NAME and its files are present - not reissuing"
    else
        if certbot certificates --cert-name "$CERT_NAME" 2>/dev/null | grep -q "Certificate Name: $CERT_NAME"; then
            warn "certbot tracks lineage $CERT_NAME but $CERTDIR/fullchain.pem is missing.
         Reissuing into the same lineage rather than trusting the bookkeeping."
        fi
        set -- certonly --webroot -w "$WEBROOT" -d "$FQDN" --cert-name "$CERT_NAME" \
               --server "$ACME_DIRECTORY" \
               --key-type rsa --rsa-key-size "$ACME_RSA_KEY_SIZE" \
               --deploy-hook 'systemctl reload nginx' \
               --non-interactive --agree-tos --keep-until-expiring
        # --deploy-hook is saved into the lineage's renewal conf as renew_hook and
        # runs on every future unattended renewal, so nginx picks up the new cert
        # without anyone touching the host.
        # --key-type rsa is required: certbot 2.x defaults to ECDSA and the
        # FreeIPA/Dogtag ACME profile rejects it at finalize.
        # --cert-name pins the lineage, so a re-run updates it instead of minting
        # a -0001 directory the vhost does not point at.
        if [ -n "$ACME_EMAIL" ]; then
            set -- "$@" -m "$ACME_EMAIL"
        else
            warn "no ACME_EMAIL set; registering without a contact address"
            set -- "$@" --register-unsafely-without-email
        fi
        certbot "$@" || die_vhost "certbot failed for $FQDN. Check that inbound :80 reaches this host and
  that http://$FQDN/.well-known/acme-challenge/ is NOT redirected to https."
    fi
    # Gated on the disk, never set unconditionally. have_cert is what decides
    # whether the TLS vhost is enabled in step 9, so it must mean "the files
    # nginx is about to open exist", not "certbot exited 0".
    if [ -f "$CERTDIR/fullchain.pem" ] && [ -f "$CERTDIR/privkey.pem" ]; then
        have_cert=1
    else
        have_cert=0
        # Not a die: the rest of the install is still worth completing. But the
        # bootstrap stub must not be left live while we say only "not enabled",
        # so the pre-run config goes back first and the warning names that.
        restore_vhost
        warn "certbot reported success but $CERTDIR/fullchain.pem or privkey.pem is still absent.
         The TLS vhost is NOT being enabled. If MCP_CERT_NAME ($CERT_NAME) does not match the
         lineage certbot actually wrote, point --cert-path at the real directory and re-run.
         The temporary 404-only bootstrap vhost has been rolled back:
         $RESTORED"
    fi
fi

# Reload nginx after a renewal, or certbot.timer quietly renews the certificate
# while nginx keeps serving the old one until a human notices. certbot persists
# --deploy-hook into the lineage's renewal conf as renew_hook, so this is set
# once at issuance and needs no file of its own.
if [ "$DRY_RUN" != 1 ] && [ "$CERT_MODE" = acme ]; then
    grep -q '^renew_hook' "/etc/letsencrypt/renewal/$CERT_NAME.conf" 2>/dev/null \
        || warn "no renew_hook in /etc/letsencrypt/renewal/$CERT_NAME.conf.
         Add one with:  certbot certonly --cert-name $CERT_NAME --deploy-hook 'systemctl reload nginx'"
fi
# The timer is certbot.timer on Debian/Ubuntu and certbot-renew.timer on RHEL.
run systemctl enable --now certbot.timer 2>/dev/null \
    || run systemctl enable --now certbot-renew.timer 2>/dev/null \
    || warn "no certbot renewal timer found; renewals will not happen automatically"

# --------------------------------------------------------------------------
# 9. ACTIVATE
# --------------------------------------------------------------------------
step "9. activate"

if [ "$have_cert" = 1 ]; then
    place_vhost "$RENDER/mcp.conf"
    if [ "$DRY_RUN" != 1 ] && ! nginx -t; then
        # Keep the config nginx rejected. Without it the operator has the error
        # text but no file to compare it against, because the rollback below is
        # about to overwrite it and the render lives in a temp tree cleanup()
        # removes on exit.
        cp -p "$RENDER/mcp.conf" "$VHOST_AVAIL.rejected" 2>/dev/null || true
        # $VHOST_AVAIL.bak is guaranteed to be what this run found, never the
        # bootstrap vhost this run wrote, so restoring it is a real rollback.
        # The three-outcome logic that used to be spelled out here now lives in
        # restore_vhost(), because step 8's failure paths need exactly the same
        # thing and a second copy of it would be a second thing to get wrong.
        # RESTORED reports which of the three outcomes actually occurred.
        die_vhost "nginx -t failed on the full vhost. nginx was NOT reloaded and mcp-server was NOT enabled.
  The rejected config is kept for inspection at $VHOST_AVAIL.rejected"
    fi
    # Disarm. The full vhost is on disk and nginx -t accepted it, so the
    # bootstrap window is closed: from here a signal must not roll anything
    # back, and $RESTORED must not be quoted at anyone as though it had.
    VHOST_ROLLBACK_ARMED=0
    RESTORED="the full vhost was installed and accepted; nothing was rolled back"
else
    # Stage the rendered vhost disabled rather than leaving nothing behind, so the
    # operator can see exactly what will be enabled and diff it. Enabling it now
    # would break nginx outright: the listen 443 block names ssl_certificate paths
    # that do not exist yet, and nginx refuses to start rather than skipping them.
    run install -m 0644 -o root -g root "$RENDER/mcp.conf" "$VHOST_AVAIL.disabled"
    # Belt and braces: the ACME path already rolls the stub back before it warns,
    # but this branch is also reachable from --cert-mode none, and staging a
    # .disabled file while a 404-only stub is the enabled config is precisely
    # the state the old message failed to describe. Calling it again is a no-op
    # when the vhost was never touched.
    restore_vhost
    warn "no certificate at $CERTDIR. The TLS vhost is NOT enabled; the MCP endpoint is NOT serving.
         The rendered config is staged at $VHOST_AVAIL.disabled.
         Missing: $CERTDIR/fullchain.pem and $CERTDIR/privkey.pem.
         Install them, then re-run with --cert-mode existing --cert-path $CERTDIR.
         Vhost state: $RESTORED"
fi

# nginx is enabled here rather than only on the ACME path, so a host installed
# with --cert-mode existing or none still comes back after a reboot.
run systemctl enable --quiet nginx 2>/dev/null || warn "could not enable nginx at boot"

run systemctl daemon-reload

run systemctl enable --quiet mcp-server \
    || die "could not enable mcp-server at boot. journalctl -u mcp-server -n 50 --no-pager"
# Restart rather than `enable --now`: `--now` starts a stopped unit and does
# nothing to a running one, so re-running this installer over a live host once
# replaced the code in CODEDIR and left the old process serving it. That failed
# silently in the worst way available: the unit was active, the verifier passed
# every check, and the only symptom was a newly added tool answering "Unknown
# tool". Restart is unconditional because by this point the code, the unit and
# the environment have all been rewritten, so there is no case where keeping
# the old process is right.
run systemctl restart mcp-server \
    || die "mcp-server failed to start. Read the real reason with:  journalctl -u mcp-server -n 50 --no-pager"

# Wait for the socket before going further. systemd reports the unit active as
# soon as the process is forked, but uvicorn binds the socket a second or two
# later, after the Python import and the MCP session manager come up. Without
# this wait the verifier runs first and reports "socket does not exist" plus
# two cascading 502s, on a perfectly good install.
#
# Only a clean host shows it. Re-running over an existing install finds the
# socket already there from the previous run, so the race is invisible exactly
# when you are most likely to be testing.
if [ "$DRY_RUN" != 1 ]; then
    _sock="$(sed -n 's/^Environment=MCP_LISTEN=//p' "$UNIT" | head -1)"
    [ -n "$_sock" ] || _sock=/run/mcp-server/mcp.sock
    case "$_sock" in
        /*)
            _w=0
            while [ "$_w" -lt 30 ]; do
                [ -S "$_sock" ] && break
                systemctl is-active --quiet mcp-server \
                    || die "mcp-server died while starting. journalctl -u mcp-server -n 50 --no-pager"
                sleep 1
                _w=$((_w + 1))
            done
            [ -S "$_sock" ] || die "mcp-server is active but never created $_sock after ${_w}s.
  The process is running, so this is not a crash: check MCP_LISTEN in the unit and
  RuntimeDirectory, then read journalctl -u mcp-server -n 50 --no-pager"
            say "PASS socket $_sock is listening (after ${_w}s)"
            ;;
        *) : ;;   # a host:port listener, nothing to wait for on the filesystem
    esac
fi

run systemctl reload nginx 2>/dev/null || run systemctl restart nginx

# --------------------------------------------------------------------------
# 10. VERIFY. The installer's exit status is the verifier's exit status.
#     The IPA authorization groups are checked there too (check 11). A group
#     that does not resolve makes authorize_tool() fail closed, so the
#     deployment looks healthy while denying every tool to every user.
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# 9b. CLIENT BUNDLE (served here by default, exported for off-band copying, or
#     both). Placed after activate so the vhost that serves it is already live,
#     and before verify so check 12 has something to check.
# --------------------------------------------------------------------------
if [ "$SERVE_CLIENT" = yes ] || [ -n "$CLIENT_EXPORT" ]; then
    # Page values, derived from what this install already knows, so a default run
    # types none of them. Each is overridable by a --client-* flag or site.env.
    # The download URL is deliberately not among them: the page infers it from
    # wherever it is served, so one bundle works from any host.
    CLIENT_DOMAIN="$(printf '%s' "$FQDN" | cut -d. -f2-)"
    CLIENT_KDC="$IPA_SERVER"
    CLIENT_MCP_URL="https://$FQDN/"
    CLIENT_ORG="${CLIENT_ORG_NAME:-$CLIENT_DOMAIN}"
    CLIENT_CA_SHA256=""
    [ -r /etc/ipa/ca.crt ] && CLIENT_CA_SHA256="$(sha256sum /etc/ipa/ca.crt 2>/dev/null | cut -d' ' -f1)"
    CLIENT_DNS="$CLIENT_DNS_IP"
    [ -n "$CLIENT_DNS" ] || CLIENT_DNS="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"

    # The contract: the client bundle is the client scripts and bridges plus the static
    # page (index.html, app.js) and config.example.js. This list is the entire
    # interface with client/README.md: a workstation that cannot fetch one of
    # them fails partway through provisioning. Kept here so bundle assembly and
    # config.js writing live in one place. config.js is written by write_config
    # below rather than copied, so config.example.js ships as the shape
    # reference and the live config.js is generated per install.
    BUNDLE_FILES="setup.sh setup.ps1 setup-macos.sh install-bridge.sh JsoncEdit.ps1 bridge/mcp-krb-bridge.py bridge/mcp-krb-remote-bridge.py bridge/mcp-fetch web/index.html web/app.js web/config.example.js"
    # Injects the site fragment into the page's markers and derives one nav
    # entry per section from its id and <h2>. Refuses a fragment that is not
    # root-owned or is group/world-writable: it becomes markup on the page that
    # tells a workstation what to run as root, so it is code by another name.
    inject_site_sections() {
        _f="$CLIENT_SITE_SECTIONS"
        case "$_f" in
            /*) ;;
            *) die "CLIENT_SITE_SECTIONS must be an absolute path, got '$_f'." ;;
        esac
        [ -f "$_f" ] || die "CLIENT_SITE_SECTIONS: no such file: $_f"
        case "$_f" in
            "$SRC"/*) die "CLIENT_SITE_SECTIONS must live outside $SRC: this script
  converges that tree on the repository's file set and would delete it." ;;
        esac
        [ "$(stat -c %U "$_f")" = root ] \
            || die "CLIENT_SITE_SECTIONS must be root-owned: $_f"
        [ "$(stat -c %a "$_f" | sed 's/.*\(..\)$/\1/')" = 44 ] \
            || [ -z "$(find "$_f" -perm /022)" ] \
            || die "CLIENT_SITE_SECTIONS must not be group- or world-writable: $_f"

        SECTIONS_FILE="$_f" /usr/bin/python3 - "$1" <<'PY' || die "injecting CLIENT_SITE_SECTIONS failed"
import os, re, sys

page = sys.argv[1]
frag = open(os.environ["SECTIONS_FILE"], encoding="utf-8").read()

with open(page, encoding="utf-8") as f:
    html = f.read()

def marker(name):
    """A marker counts only when it is alone on its line.

    Substring matching looked fine until the page's own header comment
    explained where the markers are, in prose, quoting their literal text.
    That comment sits above the real markers, so the first replacement
    landed inside it: the injected section ended up commented out and
    invisible, the real markers went untouched, and the nav gained no
    entry. Anchoring to a whole line tells prose about a marker apart from
    the marker itself.
    """
    return re.compile(r"^[ \t]*" + re.escape(name) + r"[ \t]*$", re.M)


for name in ("<!-- site-sections -->", "<!-- site-nav -->"):
    if not marker(name).search(html):
        sys.stderr.write("the page has no %s marker on a line of its own\n" % name)
        sys.exit(1)

# One nav entry per top-level section, labelled by its <h2> with any tag
# markup (icons, <span class="tag">) stripped back to plain text.
nav = []
for sid, h2 in re.findall(r'<section[^>]*\bid="([^"]+)"[^>]*>\s*<h2[^>]*>(.*?)</h2>', frag, re.S):
    # Replace tags with a space, not nothing: an <h2> ending in a
    # <span class="tag"> otherwise renders as "TitleIT only" in the nav.
    label = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", h2)).strip()
    nav.append('    <a href="#%s">%s</a>' % (sid, label))
if not nav:
    sys.stderr.write("no <section id=...><h2> found in the fragment; nothing to link\n")
    sys.exit(1)

# Lambda replacements, so a backslash in the fragment is never read as a
# group reference.
html = marker("<!-- site-nav -->").sub(lambda _: "\n".join(nav), html, count=1)
html = marker("<!-- site-sections -->").sub(lambda _: frag.rstrip(), html, count=1)

with open(page, "w", encoding="utf-8", newline="") as f:
    f.write(html)
print("  injected %d site section(s): %s" % (len(nav), ", ".join(
    re.findall(r'<section[^>]*\bid="([^"]+)"', frag))))
PY
    }

    assemble_bundle() {
        _bd="$1"; _cl="$SRC/client"
        for _f in $BUNDLE_FILES; do
            [ -f "$_cl/$_f" ] || die "the client bundle is incomplete: $_cl/$_f is missing.
  Refusing to serve a partial set that would fail a workstation partway through."
        done
        mkdir -p "$_bd"
        for _f in $BUNDLE_FILES; do
            install -m 0644 "$_cl/$_f" "$_bd/$(basename "$_f")"
        done
        # A deployment's own page sections. Same reasoning as MCP_SITE_TOOLS:
        # the content names internal hosts, so it cannot live in this repository,
        # and it must not be hand-patched into the served copy either, because
        # the next install would overwrite it and nothing would regenerate it.
        [ -n "$CLIENT_SITE_SECTIONS" ] && inject_site_sections "$_bd/index.html"

        # Converge, do not merely add. This step used to only install, so any
        # file ever published stayed published: after install.sh was renamed to
        # install-bridge.sh, hosts went on serving BOTH, and the stale one was a
        # root-installing script nobody intended to offer. That is the opposite
        # of what [SC1] claims, where the whole assurance is that the publisher
        # controls exactly which bytes run as root on a workstation.
        #
        # config.js is generated by write_config() right after this, so it is
        # kept rather than pruned.
        for _p in "$_bd"/*; do
            [ -e "$_p" ] || continue
            _n="$(basename "$_p")"
            [ "$_n" = config.js ] && continue
            for _f in $BUNDLE_FILES; do
                [ "$_n" = "$(basename "$_f")" ] && { _n=""; break; }
            done
            [ -n "$_n" ] || continue
            say "pruning stale published file: $_n"
            rm -f "$_p"
        done
    }

    # config.js is a flat window.SITE = {...} the static page reads at runtime.
    # Values are JS single-quoted strings, so escape backslash then quote. printf
    # per line, not a heredoc, so nothing depends on a column-0 terminator.
    js_str() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g"; }
    write_config() {
        {
            printf '%s\n' "/* Generated by server/install/run.sh, regenerated on every install."
            printf '%s\n' "   Do not hand-edit: change the installer inputs or site.env. The page's"
            printf '%s\n' "   download URL is here only if the files are not beside the page; blank"
            printf '%s
' "   means the page infers it from where it was served. */"
            printf '%s\n' "window.SITE = {"
            printf "  orgName: '%s',\n"      "$(js_str "$CLIENT_ORG")"
            printf "  domain: '%s',\n"       "$(js_str "$CLIENT_DOMAIN")"
            printf "  realm: '%s',\n"        "$(js_str "$REALM")"
            printf "  kdc: '%s',\n"          "$(js_str "$CLIENT_KDC")"
            printf "  mcpUrl: '%s',\n"       "$(js_str "$CLIENT_MCP_URL")"
            printf "  caSha256: '%s',\n"     "$(js_str "$CLIENT_CA_SHA256")"
            printf "  dnsIp: '%s',\n"        "$(js_str "$CLIENT_DNS")"
            printf "  supportEmail: '%s',\n" "$(js_str "$CLIENT_SUPPORT_EMAIL")"
            # Blank is the normal case and means "the directory this page came
            # from". Only a host that serves the page and the files from
            # different paths needs it set.
            printf "  downloadBase: '%s',\n" "$(js_str "$CLIENT_DOWNLOAD_BASE")"
            # Drives whether the page shows the CA step at all, and which
            # argument the macOS command carries.
            printf "  caInstall: %s\n" "$([ "$CLIENT_CA_INSTALL" = yes ] && echo true || echo false)"
            printf '%s\n' "};"
        } > "$1/config.js"
        chmod 0644 "$1/config.js"
    }

    if [ "$SERVE_CLIENT" = yes ]; then
        step "9b. client bundle -> $CLIENT_ROOT (served at $CLIENT_PATH)"
        if [ "$DRY_RUN" = 1 ]; then
            say "  would assemble the bundle in $CLIENT_ROOT and write config.js from derived values"
        else
            assemble_bundle "$CLIENT_ROOT"
            write_config "$CLIENT_ROOT"
            # nginx has to traverse to them. 0755 on the directory, 0644 on the
            # files: the same reasoning as RuntimeDirectoryMode, where 0750
            # produced a 502 that read as 'No such file or directory'.
            run chmod 0755 "$CLIENT_ROOT"
        fi
    fi

    if [ -n "$CLIENT_EXPORT" ]; then
        step "9b. client bundle -> $CLIENT_EXPORT (export for off-band copying)"
        if [ "$DRY_RUN" = 1 ]; then
            say "  would assemble the bundle in $CLIENT_EXPORT and write config.js from derived values"
        else
            assemble_bundle "$CLIENT_EXPORT"
            write_config "$CLIENT_EXPORT"
            say "  exported to $CLIENT_EXPORT. Copy it to whatever host serves your static"
            say "  files. The page infers its own URL, so there is no per-host config."
        fi
    fi
fi

step "10. verify"

if [ "$DRY_RUN" = 1 ]; then
    say "  would run: sh $INSTALLDIR/verify.sh $FQDN"
    exit 0
fi
[ -f "$INSTALLDIR/verify.sh" ] || die "server/install/verify.sh is missing; the install is unverified"
# The lineage name has to cross the exec. site.env was sourced without exporting,
# so without this the verifier falls back to $FQDN and reports a missing renewal
# config on any host where MCP_CERT_NAME names a different lineage.
MCP_CERT_NAME="$CERT_NAME"; export MCP_CERT_NAME
# WEBROOT crosses too, so check 6 can assert a real 200 on the probe written in
# step 7 rather than accepting a 404 it cannot interpret.
export WEBROOT
# And SITE_ENV, so the verifier's remediation text names the file this install
# actually used. Without it check 6 printed "WEBROOT in /etc/mcp-server/site.env"
# on a run driven by --site-env /root/site-mcp.env, sending the operator to
# edit a file that may not even exist.
export SITE_ENV
# exec, so the installer's exit status is the verifier's. cleanup() cannot run
# across exec, so the temp tree is removed first.
cleanup
trap - EXIT INT TERM HUP
# Unset KRB5CCNAME before the exec, and after cleanup() has deleted the tree it
# points into. Step 5 exports KRB5CCNAME=FILE:$TMPROOT/cc/ccache for the private
# host ticket; leaving it exported across the exec pointed the verifier at a
# path that no longer exists, so its `klist -s` always failed and check 10 (the
# authenticated SPNEGO round trip, the single most valuable check in the script)
# reported SKIP on every install, even for a root session holding a perfectly
# good ticket in /tmp/krb5cc_0. The verifier must fall back to the ambient
# default ccache, which is what a human re-running it by hand would get.
unset KRB5CCNAME
exec sh "$INSTALLDIR/verify.sh" "$FQDN"
