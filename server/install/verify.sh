#!/bin/sh
# verify.sh - read-only post-install verifier for the MCP host.
#
#   sudo sh server/install/verify.sh [fqdn] [--site-env PATH]
#
# Run as the last step of run.sh and as the closing item of the
# SECURITY.md deployment checklist. Re-runnable at any time.
#
# Every failure this repo has actually suffered was invisible: the service
# reported healthy while the ACME challenge 401'd with ninety days still on the
# certificate, the keytab was unreadable by the account that had to open it,
# and the authorization groups denied everyone. This script makes each of
# those loud.
#
# It mutates nothing. No chmod, no reload, no writes outside a temp directory
# that is removed on exit. Full TLS verification everywhere; never -k.
# It never prints key material, an Authorization header, or a token.
#
# set -u but deliberately not -e: every check must run so the operator sees
# the whole picture rather than only the first failure.
set -u

# --------------------------------------------------------------------------
# Site values: argument, then environment, then site.env, then the hostname.
#
# site.env is read, never sourced: this script promises to mutate nothing, and
# sourcing a file as root to read four strings out of it is a side effect
# waiting to happen. site_val greps out a plain KEY=value assignment, which is
# all site.env.example is allowed to contain anyway.
#
# The MCP_HOST/MCP_FQDN pair is resolved bidirectionally here, matching run.sh.
# Reading only MCP_FQDN here while the installer read only MCP_HOST is how the
# two once disagreed about which host they were talking about.
# --------------------------------------------------------------------------
# Which site.env: --site-env wins, then $SITE_ENV from the environment, then
# the default path. All three are reported, because getting this wrong is
# silent.
#
# run.sh sources site.env without exporting and then execs this script,
# exporting only the values it knows this verifier needs. A run driven by
# `run.sh --site-env /root/site-mcp.env` used to land here with SITE_ENV unset
# and fell back to /etc/mcp-server/site.env without a word. The needed values
# were already in the environment, so nothing failed; what broke was check 6's
# remediation text, which quoted the default path and sent the operator to
# edit a file that may not even exist. The installer now exports SITE_ENV, and
# this accepts it explicitly either way, so a standalone run can be pointed at
# the right file too.
SITE_ENV="${SITE_ENV:-/etc/mcp-server/site.env}"
SITE_ENV_SOURCE=default
[ "${SITE_ENV:-}" = /etc/mcp-server/site.env ] || SITE_ENV_SOURCE=environment

ARG_FQDN=""
while [ $# -gt 0 ]; do
    case "$1" in
        --site-env)
            # Explicit arity check: under a bare `--site-env` at the end of the
            # line, "$2" would be an unbound-variable death instead of a hint.
            [ $# -ge 2 ] || { echo "ERROR: --site-env needs a path" >&2; exit 2; }
            SITE_ENV="$2"; SITE_ENV_SOURCE="--site-env"; shift ;;
        --site-env=*)
            SITE_ENV="${1#--site-env=}"; SITE_ENV_SOURCE="--site-env" ;;
        -h|--help)
            echo "usage: sudo sh verify.sh [fqdn] [--site-env PATH]"
            exit 0 ;;
        -*) echo "ERROR: unknown option: $1" >&2; exit 2 ;;
        *)
            [ -z "$ARG_FQDN" ] || { echo "ERROR: unexpected extra argument: $1" >&2; exit 2; }
            ARG_FQDN="$1" ;;
    esac
    shift
done

site_val() {
    [ -r "$SITE_ENV" ] || return 0
    sed -n "s/^[[:space:]]*$1=//p" "$SITE_ENV" | tail -1 | sed 's/^"\(.*\)"$/\1/; s/^'\''\(.*\)'\''$/\1/'
}

FQDN="${ARG_FQDN:-${MCP_FQDN:-${MCP_HOST:-}}}"
[ -n "$FQDN" ] || FQDN="$(site_val MCP_HOST)"
[ -n "$FQDN" ] || FQDN="$(site_val MCP_FQDN)"
[ -n "$FQDN" ] || FQDN="$(hostname -f 2>/dev/null || hostname)"

# The lineage name and the ACME docroot come from the installer's environment
# across its exec, and fall back to site.env for a standalone run.
MCP_CERT_NAME="${MCP_CERT_NAME:-$(site_val MCP_CERT_NAME)}"
[ -n "$MCP_CERT_NAME" ] || MCP_CERT_NAME="$FQDN"
WEBROOT="${WEBROOT:-$(site_val WEBROOT)}"
[ -n "$WEBROOT" ] || WEBROOT=/var/www/html

UNIT_NAME="${MCP_UNIT:-$(site_val MCP_UNIT)}"
[ -n "$UNIT_NAME" ] || UNIT_NAME=mcp-server

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

FAILED=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILED=$((FAILED + 1)); }
skip() { printf 'SKIP  %s\n' "$*"; }
info() { printf '      %s\n' "$*"; }
head2() { printf '\n-- %s\n' "$*"; }

printf 'verify.sh: %s (unit %s)\n' "$FQDN" "$UNIT_NAME"
# Half the remediation text below quotes this path, so every run names the
# file that was actually consulted.
if [ -r "$SITE_ENV" ]; then
    printf 'site.env:          %s (from %s)\n' "$SITE_ENV" "$SITE_ENV_SOURCE"
else
    printf 'site.env:          %s (from %s) - NOT READABLE, using defaults and the environment\n' \
        "$SITE_ENV" "$SITE_ENV_SOURCE"
fi
[ "$(id -u)" = 0 ] || printf '\nNOTE: not running as root; the keytab and socket checks will be skipped.\n'

# --------------------------------------------------------------------------
# Read the installed configuration rather than assuming it. The unit is the
# source of truth for the SPN, the socket path and the service user, so this
# verifier cannot drift away from what actually runs.
# --------------------------------------------------------------------------
UNIT_ENV="$(systemctl show -p Environment --value "$UNIT_NAME" 2>/dev/null || true)"
[ -n "$UNIT_ENV" ] || UNIT_ENV="$(systemctl show -p Environment "$UNIT_NAME" 2>/dev/null | sed 's/^Environment=//' || true)"
env_val() { printf '%s\n' "$UNIT_ENV" | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1; }

MCP_SPN="$(env_val MCP_SPN)"
SOCKET="$(env_val MCP_LISTEN)"
KEYTAB="$(env_val KRB5_KTNAME)"
SVCUSER="$(systemctl show -p User --value "$UNIT_NAME" 2>/dev/null || true)"
[ -n "$SVCUSER" ] || SVCUSER=mcp
SVCGROUP="$(systemctl show -p Group --value "$UNIT_NAME" 2>/dev/null || true)"
[ -n "$SVCGROUP" ] || SVCGROUP="$SVCUSER"
[ -n "$KEYTAB" ] || KEYTAB=/etc/mcp-server/krb5.keytab
CONFDIR="$(dirname "$KEYTAB")"

# MCP_SPN is the gssapi service@host form; the keytab lists the Kerberos
# HTTP/host@REALM form. Convert once so the two can be compared.
SPN_KRB=""
case "$MCP_SPN" in
    *@*) SPN_KRB="$(printf '%s' "$MCP_SPN" | sed 's/@/\//')" ;;
esac

info "service user: $SVCUSER:$SVCGROUP"
info "keytab: $KEYTAB   socket: ${SOCKET:-<unset>}"

# nginx's runtime user, discovered from a live worker and then from the config.
# Not hardcoded to www-data: RHEL runs nginx as 'nginx'.
NGINXUSER="$(ps -o user=,args= -C nginx 2>/dev/null | awk '/worker process/{print $1; exit}')"
if [ -z "$NGINXUSER" ]; then
    NGINXUSER="$(nginx -T 2>/dev/null | sed -n 's/^ *user  *\([A-Za-z0-9_-]*\).*;/\1/p' | head -1)"
fi
[ -n "$NGINXUSER" ] || NGINXUSER=www-data
info "nginx runtime user: $NGINXUSER"

# --------------------------------------------------------------------------
head2 "1. service state"
# --------------------------------------------------------------------------
if systemctl is-active --quiet "$UNIT_NAME"; then
    pass "$UNIT_NAME is active"
else
    fail "$UNIT_NAME is not active"
    info "journalctl -u $UNIT_NAME -n 50 --no-pager"
fi
if systemctl is-enabled --quiet "$UNIT_NAME" 2>/dev/null; then
    pass "$UNIT_NAME is enabled at boot"
else
    fail "$UNIT_NAME is not enabled; it will not come back after a reboot"
fi

# --------------------------------------------------------------------------
head2 "2. proxy socket reachable by nginx"
# --------------------------------------------------------------------------
if [ -z "$SOCKET" ]; then
    fail "the unit declares no MCP_LISTEN, so the socket path is unknown"
elif [ ! -S "$SOCKET" ]; then
    fail "$SOCKET does not exist or is not a socket"
else
    pass "$SOCKET exists"
    # Mode matters as much as existence. uvicorn creates a uds at 0666, which
    # lets any local account able to traverse the directory speak HTTP straight
    # to the app, skipping nginx's rate limit, its body cap and the
    # X-Forwarded-For overwrite that audit attribution rests on. Socket
    # activation exists to make it 0660 with nginx's group.
    _sm="$(stat -c %a "$SOCKET" 2>/dev/null)"
    _sg="$(stat -c %G "$SOCKET" 2>/dev/null)"
    case "$_sm" in
        660|640|600) pass "socket mode $_sm (group $_sg): not world-reachable" ;;
        *) fail "socket mode is $_sm, so any local account can bypass nginx entirely"
           info "that discards the rate limit, the 1 MB body cap, and the"
           info "X-Forwarded-For overwrite the audit trail depends on"
           info "fix: install server/install/mcp-server.socket and re-run; systemd"
           info "creates the socket 0660 with nginx's group, which the service"
           info "cannot do itself (no CAP_CHOWN under this sandbox)" ;;
    esac
    SOCKDIR="$(dirname "$SOCKET")"
    DIRMODE="$(stat -c '%a' "$SOCKDIR" 2>/dev/null || echo '?')"
    if [ "$DIRMODE" = 755 ]; then
        pass "$SOCKDIR is 0755 (nginx can traverse it)"
    else
        fail "$SOCKDIR is $DIRMODE, expected 755"
        # 0750 here is the classic one: the socket exists, nginx returns 502
        # 'No such file or directory', and the real cause is the parent dir.
        info "set RuntimeDirectoryMode=0755 in the unit; with 0750 nginx returns 502"
    fi
    if [ "$(id -u)" = 0 ]; then
        if runuser -u "$NGINXUSER" -- test -r "$SOCKET" 2>/dev/null; then
            pass "$NGINXUSER can read $SOCKET"
        else
            fail "$NGINXUSER cannot read $SOCKET"
        fi
    else
        skip "socket readability as $NGINXUSER (needs root)"
    fi
fi

# --------------------------------------------------------------------------
head2 "3. keytab readable by the service account"
# --------------------------------------------------------------------------
if [ "$(id -u)" != 0 ]; then
    skip "keytab checks (need root)"
elif [ ! -f "$KEYTAB" ]; then
    fail "$KEYTAB does not exist"
else
    # klist -k exits 0 on a readable but empty keytab, so the SPN has to be
    # matched explicitly. Only principal names are printed, never key material.
    if runuser -u "$SVCUSER" -- klist -k "$KEYTAB" >"$TMP/kt" 2>/dev/null; then
        pass "$SVCUSER can read $KEYTAB"
        sed -n 's/^ *\([0-9][0-9]*\) \(.*\)$/      kvno \1  \2/p' "$TMP/kt"
    else
        fail "$SVCUSER cannot read $KEYTAB"
        # This is the exact first-boot outage, whose only symptom in the log is
        # 'MissingCredentialsError ... Major (458752) / Minor (13): Permission denied'.
        info "remediation: chown root:$SVCGROUP $CONFDIR $KEYTAB && chmod 0750 $CONFDIR && chmod 0640 $KEYTAB"
    fi
fi

# --------------------------------------------------------------------------
head2 "4. keytab holds the SPN the server accepts for"
# --------------------------------------------------------------------------
if [ "$(id -u)" != 0 ] || [ ! -f "$KEYTAB" ]; then
    skip "SPN check"
elif [ -z "$SPN_KRB" ]; then
    fail "the unit declares no usable MCP_SPN, so the keytab cannot be checked against it"
elif klist -k "$KEYTAB" 2>/dev/null | grep -q "$SPN_KRB@"; then
    pass "$KEYTAB contains $SPN_KRB@<realm> (MCP_SPN=$MCP_SPN)"
else
    fail "$KEYTAB does NOT contain $SPN_KRB@<realm>; every handshake will fail"
    info "an IPA admin creates it with:  ipa service-add $SPN_KRB"
fi

# --------------------------------------------------------------------------
head2 "5. credential file permissions"
# --------------------------------------------------------------------------
# The single keytab contract: the acceptor opens the keytab itself, so the
# service group must be able to read it and nobody else may.
# Asserted only. This script never chmods.
WANT_DIR="750 root:$SVCGROUP"; WANT_KT="640 root:$SVCGROUP"
if [ ! -d "$CONFDIR" ]; then
    fail "$CONFDIR does not exist"
else
    D_OWN="$(stat -c '%U:%G' "$CONFDIR")"; D_MODE="$(stat -c '%a' "$CONFDIR")"
    if [ "$D_MODE $D_OWN" = "$WANT_DIR" ]; then
        pass "$CONFDIR is $D_MODE $D_OWN"
    else
        fail "$CONFDIR is $D_MODE $D_OWN, expected $WANT_DIR"
    fi
    if [ -f "$KEYTAB" ]; then
        K_OWN="$(stat -c '%U:%G' "$KEYTAB")"; K_MODE="$(stat -c '%a' "$KEYTAB")"
        if [ "$K_MODE $K_OWN" = "$WANT_KT" ]; then
            pass "$KEYTAB is $K_MODE $K_OWN"
        else
            fail "$KEYTAB is $K_MODE $K_OWN, expected $WANT_KT"
        fi
    fi
fi

# --------------------------------------------------------------------------
head2 "6. ACME challenge path is not redirected"
# --------------------------------------------------------------------------
# The historical bug: the port-80 block 308-redirects /.well-known/acme-challenge/
# to HTTPS, which is Kerberos-gated and answers 401, so the next http-01 renewal
# fails and the certificate quietly expires.
#
# A 404 used to be accepted here as a PASS, on the reasoning that it proves
# nginx served the location itself instead of bouncing it to TLS. True, but not
# enough: it cannot distinguish that from nginx serving the challenge out of a
# different root than the one certbot writes into, which issues fine and then
# 404s every renewal for the rest of the certificate's life. Same silent
# expiry, different cause.
#
# So run.sh drops a static probe file into $WEBROOT, and when that file is
# present on disk the correct answer is 200 and only 200. On a host this
# verifier was pointed at without the installer having run, the file is absent
# and the old 200-or-404 judgement is all that is available.
PROBE_NAME=verify-install-probe
PROBE_LOCAL="$WEBROOT/.well-known/acme-challenge/$PROBE_NAME"
PROBE="http://$FQDN/.well-known/acme-challenge/$PROBE_NAME"
ACODE="$(curl -sS --max-time 10 -o "$TMP/probe" -w '%{http_code}' "$PROBE" 2>/dev/null)"
[ -n "$ACODE" ] || ACODE=000

if [ -f "$PROBE_LOCAL" ]; then
    info "probe file present at $PROBE_LOCAL (WEBROOT=$WEBROOT)"
    case "$ACODE" in
        200)
            if cmp -s "$PROBE_LOCAL" "$TMP/probe"; then
                pass "port 80 serves $WEBROOT/.well-known/acme-challenge/ directly (HTTP 200, contents match)"
                info "the vhost root and the certbot -w webroot are the same directory"
            else
                fail "HTTP 200 but the body does not match $PROBE_LOCAL"
                info "something else is answering this path; renewal may still write to the wrong place"
            fi ;;
        404)
            fail "the ACME probe exists at $PROBE_LOCAL but port 80 returns 404"
            info "nginx is serving /.well-known/acme-challenge/ from a DIFFERENT root than \$WEBROOT."
            info "Issuance succeeds through the temporary bootstrap vhost and EVERY RENEWAL FAILS,"
            info "so the certificate expires silently about ninety days from issuance."
            info "Compare, and make all three agree:"
            info "  WEBROOT in $SITE_ENV                        = $WEBROOT"
            info "  root in the listen 80 acme-challenge location (nginx -T | grep -A1 acme-challenge)"
            info "  webroot_path in /etc/letsencrypt/renewal/$MCP_CERT_NAME.conf"
            info "Then re-run server/install/run.sh, which substitutes {{WEBROOT}} into both." ;;
        30*)
            fail "port 80 REDIRECTS the ACME challenge (HTTP $ACODE); the next renewal will fail"
            info "add to the listen 80 block, ABOVE the redirect:"
            info "  location ^~ /.well-known/acme-challenge/ { root $WEBROOT; }"
            info "and keep the 308 inside  location / { return 308 https://\$host\$request_uri; }" ;;
        000)
            fail "port 80 on $FQDN is unreachable; http-01 renewal cannot work" ;;
        *)
            fail "unexpected HTTP $ACODE from $PROBE" ;;
    esac
else
    case "$ACODE" in
        200|404) pass "port 80 serves the ACME challenge path directly (HTTP $ACODE, no redirect)"
                 info "no probe file at $PROBE_LOCAL, so the vhost root could not be compared with"
                 info "\$WEBROOT. Run server/install/run.sh to place it and re-run this check." ;;
        30*)     fail "port 80 REDIRECTS the ACME challenge (HTTP $ACODE); the next renewal will fail"
                 info "add to the listen 80 block, ABOVE the redirect:"
                 info "  location ^~ /.well-known/acme-challenge/ { root $WEBROOT; }"
                 info "and keep the 308 inside  location / { return 308 https://\$host\$request_uri; }" ;;
        000)     fail "port 80 on $FQDN is unreachable; http-01 renewal cannot work" ;;
        *)       fail "unexpected HTTP $ACODE from $PROBE" ;;
    esac
fi

# The renewal conf's webroot_path is the value certbot will actually use next
# time. Compare it with $WEBROOT directly rather than inferring it from a probe.
RCONF_EARLY="/etc/letsencrypt/renewal/$MCP_CERT_NAME.conf"
if [ -r "$RCONF_EARLY" ]; then
    WP="$(sed -n 's/^[[:space:]]*webroot_path[[:space:]]*=[[:space:]]*//p' "$RCONF_EARLY" | tail -1 | sed 's/,.*$//')"
    if [ -z "$WP" ]; then
        info "no webroot_path in $RCONF_EARLY (an authenticator other than webroot?)"
    elif [ "$WP" = "$WEBROOT" ]; then
        pass "certbot renews from webroot_path=$WP, which matches WEBROOT"
    else
        fail "certbot renews from webroot_path=$WP but WEBROOT is $WEBROOT"
        info "the vhost and the renewal config disagree; renewal will 404"
    fi
fi

# --------------------------------------------------------------------------
head2 "7. renewal configuration"
# --------------------------------------------------------------------------
# The lineage is named by --cert-name, which defaults to the FQDN but can be
# set to MCP_CERT_NAME in site.env. It is honoured here; otherwise a renamed
# lineage FAILs falsely.
RCONF="/etc/letsencrypt/renewal/$MCP_CERT_NAME.conf"
if [ -f "$RCONF" ]; then
    pass "certbot renewal config exists: $RCONF"
    grep -q '^key_type *= *rsa' "$RCONF" \
        && pass "key_type = rsa (required: the FreeIPA/Dogtag ACME profile does not issue ECDSA)" \
        || fail "key_type is not rsa in $RCONF; renewal will be rejected at finalize"
else
    fail "no certbot renewal config at $RCONF"
fi
# A reload on renewal, by either mechanism certbot supports: renew_hook in this
# lineage's conf (what --deploy-hook writes), or a script in the global deploy
# directory. Without one, certbot.timer renews unattended and nginx keeps
# presenting the old certificate until somebody reloads it by hand.
if grep -q '^renew_hook' "$RCONF" 2>/dev/null; then
    pass "renew_hook set in $RCONF"
elif [ -n "$(ls -A /etc/letsencrypt/renewal-hooks/deploy 2>/dev/null)" ]; then
    pass "a global certbot deploy hook is present"
else
    fail "nothing reloads nginx after a renewal"
    info "fix: certbot certonly --cert-name $MCP_CERT_NAME --deploy-hook 'systemctl reload nginx'"
fi
if systemctl is-enabled --quiet certbot.timer 2>/dev/null \
   || systemctl is-enabled --quiet certbot-renew.timer 2>/dev/null; then
    pass "a certbot renewal timer is enabled"
else
    fail "no certbot renewal timer is enabled; the certificate will expire"
fi

# --------------------------------------------------------------------------
head2 "8. served certificate"
# --------------------------------------------------------------------------
if command -v openssl >/dev/null 2>&1; then
    if openssl s_client -connect "$FQDN:443" -servername "$FQDN" </dev/null 2>/dev/null \
        | openssl x509 -noout -subject -ext subjectAltName -enddate > "$TMP/cert" 2>/dev/null; then
        if grep -q "DNS:$FQDN\b" "$TMP/cert" || grep -q "CN *= *$FQDN" "$TMP/cert"; then
            pass "the served certificate names $FQDN"
        else
            fail "the served certificate does not name $FQDN"
            sed 's/^/      /' "$TMP/cert"
        fi
        # 30 days = 2592000 seconds. Anything less is an operational emergency
        # on a 90-day lineage that renews unattended.
        if openssl s_client -connect "$FQDN:443" -servername "$FQDN" </dev/null 2>/dev/null \
            | openssl x509 -noout -checkend 2592000 >/dev/null 2>&1; then
            pass "more than 30 days of validity remain ($(sed -n 's/^notAfter=/expires /p' "$TMP/cert"))"
        else
            fail "fewer than 30 days of validity remain ($(sed -n 's/^notAfter=/expires /p' "$TMP/cert"))"
        fi
    else
        fail "could not retrieve a certificate from $FQDN:443"
    fi
else
    skip "certificate inspection (openssl not installed)"
fi

# --------------------------------------------------------------------------
head2 "9. unauthenticated request is challenged"
# --------------------------------------------------------------------------
# Full TLS verification on purpose. If this fails on trust, the realm CA is not
# in the system store, which is itself the finding.
UCODE="$(curl --proto '=https' --tlsv1.2 -sS --max-time 15 -X POST \
              -H 'Content-Type: application/json' -d '{}' \
              -D "$TMP/hdr" -o /dev/null -w '%{http_code}' "https://$FQDN/" 2>"$TMP/err")"
[ -n "$UCODE" ] || UCODE=000
if [ "$UCODE" = 401 ]; then
    if grep -qi '^WWW-Authenticate: *Negotiate' "$TMP/hdr"; then
        pass "unauthenticated POST -> 401 with WWW-Authenticate: Negotiate"
    else
        fail "unauthenticated POST -> 401 but no 'WWW-Authenticate: Negotiate' header"
        info "clients will never attempt SPNEGO without that challenge"
    fi
elif [ "$UCODE" = 000 ]; then
    fail "could not reach https://$FQDN/ ($(head -1 "$TMP/err" 2>/dev/null))"
else
    fail "unauthenticated POST -> $UCODE, expected 401"
fi

# --------------------------------------------------------------------------
head2 "10. authenticated SPNEGO round trip"
# --------------------------------------------------------------------------
if ! klist -s 2>/dev/null; then
    # The verifier must never obtain a ticket for itself, so this is a SKIP and
    # not a failure. It is the one check a human has to close.
    skip "no Kerberos ticket in this session, so the authenticated path is untested"
    info "close it by hand:  kinit <you> && sh $0 $FQDN"
else
    REQ='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"verify-install","version":"1"}}}'
    # --negotiate -u : uses the ambient ticket. The Authorization header curl
    # builds is never printed, here or anywhere else in this script.
    ACODE2="$(curl --proto '=https' --tlsv1.2 -sS --max-time 20 --negotiate -u : \
                   -X POST -H 'Content-Type: application/json' \
                   -H 'Accept: application/json, text/event-stream' \
                   -d "$REQ" -o "$TMP/body" -w '%{http_code}' "https://$FQDN/" 2>/dev/null)"
    [ -n "$ACODE2" ] || ACODE2=000
    case "$ACODE2" in
        200|202) pass "authenticated MCP initialize -> $ACODE2 as $(klist 2>/dev/null | sed -n 's/^Default principal: //p')" ;;
        401)
            # A 401 here has two very different causes and they need different
            # answers. The common one after a fresh install or a keytab rotation
            # is a stale cached ticket: re-retrieving the keytab bumps the kvno,
            # so any service ticket obtained beforehand no longer decrypts. The
            # acceptor is fine; the ticket is simply out of date.
            #
            # Distinguished read-only, by age: a cached service ticket issued
            # before the keytab was last written cannot match the current key.
            # This script mutates nothing, so it diagnoses and tells the operator
            # what to run rather than running kdestroy on their session.
            _stale=0
            if [ -r "$KEYTAB" ]; then
                _kt_age="$(stat -c %Y "$KEYTAB" 2>/dev/null || echo 0)"
                _tk_line="$(klist 2>/dev/null | grep -F "$SPN_KRB" | head -1)"
                if [ -n "$_tk_line" ] && [ "$_kt_age" != 0 ]; then
                    _tk_epoch="$(date -d "$(echo "$_tk_line" | awk '{print $1" "$2}')" +%s 2>/dev/null || echo 0)"
                    [ "$_tk_epoch" != 0 ] && [ "$_tk_epoch" -lt "$_kt_age" ] && _stale=1
                fi
            fi
            if [ "$_stale" = 1 ]; then
                fail "authenticated request returns 401, and your cached ticket is OLDER than the keytab"
                info "the keytab was re-retrieved after that ticket was issued, which bumps the"
                info "kvno, so the ticket can no longer decrypt. The acceptor is probably fine."
                info "fix:  kdestroy -A && kinit <you> && sh $0 $FQDN"
            else
                fail "authenticated request still returns 401; the acceptor rejected the ticket"
                info "if the keytab was re-retrieved after you got your ticket, it is stale:"
                info "  kdestroy -A && kinit <you> && sh $0 $FQDN"
                info "otherwise check clock skew, the SPN in the keytab, and MCP_REALM in the unit"
            fi ;;
        *)       fail "authenticated MCP initialize -> $ACODE2" ;;
    esac
fi

# --------------------------------------------------------------------------
head2 "11. authorization groups resolve on this host"
# --------------------------------------------------------------------------
# The failure this catches is invisible: authz.authorize_tool() fails closed,
# so a group that does not resolve here means the tool denies every user
# forever while the service, the certificate and the SPNEGO handshake all look
# healthy. A denial for "you are not in the group" and a denial for "the group
# does not exist" are byte-identical from outside.
#
# getent rather than `ipa group-show`: the question that actually decides the
# outcome is whether this host resolves the name through nss/SSSD, which is
# the exact lookup authz.ipa_groups() performs. The two come apart routinely. A
# group created non-POSIX in the web UI (an ordinary choice in the same dialog)
# has no gid, so it looks correct in IPA and is invisible here.
#
# Group names are derived from the installed authz.py, never written here, so
# this check cannot drift away from the policy it is checking.
CODEDIR="$(systemctl show -p WorkingDirectory --value "$UNIT_NAME" 2>/dev/null || true)"
[ -n "$CODEDIR" ] || CODEDIR=/opt/mcp-server
POLICY_FILE="$(env_val MCP_POLICY_FILE)"

if [ ! -r "$CODEDIR/authz.py" ]; then
    fail "cannot read $CODEDIR/authz.py, so the policy groups are unknown"
elif ! command -v python3 >/dev/null 2>&1; then
    skip "python3 not available to read the policy from authz.py"
else
    GROUPS="$(MCP_POLICY_FILE="$POLICY_FILE" MCP_SITE_TOOLS_FILE="$(env_val MCP_SITE_TOOLS)" \
              python3 - "$CODEDIR" 2>"$TMP/gerr" <<'PY'
import json, os, re, sys
sys.path.insert(0, sys.argv[1])
import authz

names = set()
def collect(mapping):
    for value in mapping.values():
        if value is authz.ANY_AUTHENTICATED:   # sentinel: no group backs it
            continue
        names.update(value)

# authz.TOOL_GROUPS holds only the tools this repository ships. A deployment's
# own tools live in MCP_SITE_TOOLS and register themselves at startup, so
# importing authz alone sees four names while the overlay legitimately carries
# every tool the server actually publishes. Validating the overlay against the
# short list then rejected the site's real policy with 'unknown tool: <name>',
# and the check reported the whole policy unreadable while the running server
# was applying it perfectly. Read the registrations out of the site file so the
# known set here matches the one the server builds.
#
# Scan the whole DIRECTORY, not only the file MCP_SITE_TOOLS names. The loader
# takes exactly one file, so any deployment with more than a handful of tools
# ends up with that file as a barrel importing siblings beside it, and most of
# the registrations live in the siblings. Reading only the named file found 4 of
# 16 on a real host and failed this check on tools the running server was
# serving perfectly, which is the worst kind of red: it teaches people to ignore
# the verifier.
known = set(authz.TOOL_GROUPS)
site = os.environ.get('MCP_SITE_TOOLS_FILE', '')
if site and os.path.exists(site):
    _dir = os.path.dirname(os.path.abspath(site))
    for _name in sorted(os.listdir(_dir)):
        if not _name.endswith('.py'):
            continue
        try:
            with open(os.path.join(_dir, _name), 'r', encoding='utf-8') as fh:
                known.update(re.findall(
                    r"register_tool_policy\(\s*['\"]([A-Za-z0-9_]+)['\"]", fh.read()))
        except OSError:
            pass   # unreadable sibling; the overlay check below reports the effect

# The EFFECTIVE policy, defaults with the overlay merged over the top, which is
# what the server builds and therefore what actually decides access. Taking the
# union of both instead would report groups that no longer decide anything: an
# overlay entry REPLACES the in-code default for that tool, so a placeholder
# group named only by a shadowed default would be flagged as missing while
# nothing ever consults it.
effective = dict(authz.TOOL_GROUPS)
overlay = os.environ.get('MCP_POLICY_FILE', '')
if overlay and os.path.exists(overlay):
    # A rejected overlay fails loudly here: the running server is refusing it
    # too, and its groups would be missing from everything below.
    with open(overlay, 'r', encoding='utf-8') as fh:
        effective.update(authz.policy_from_json(json.load(fh), known_tools=known))
collect(effective)
for n in sorted(names):
    print(n)
PY
)" || GROUPS=""
    if [ -z "$GROUPS" ] && [ -s "$TMP/gerr" ]; then
        fail "could not read the policy groups from $CODEDIR/authz.py"
        info "$(head -3 "$TMP/gerr")"
    elif [ -z "$GROUPS" ]; then
        pass "no tool requires a group (every tool is open to any authenticated principal)"
    else
        missing=""
        for g in $GROUPS; do
            if getent group "$g" >/dev/null 2>&1; then
                pass "group resolves: $g"
            else
                fail "group does NOT resolve on this host: $g"
                missing="$missing $g"
            fi
        done
        if [ -n "$missing" ]; then
            info "every tool requiring$missing denies EVERY user until this is fixed"
            info "create each as a POSIX group in IPA, then re-run. A non-POSIX group has"
            info "no gid and stays invisible here no matter how correct it looks in the UI"
            info "if it was just created:  sss_cache -E   (clears the negative cache)"
        fi
    fi
fi

# --------------------------------------------------------------------------
head2 "12. client bundle, if this host serves it"
# --------------------------------------------------------------------------
# Serving is the default, so this check runs unless SERVE_CLIENT=no. What
# matters is not just "are they there" but "are they reachable without a
# ticket": a machine being provisioned has none, so if these ended up behind
# the SPNEGO gate the bootstrap deadlocks, and only for new machines while
# every existing one keeps working, the hardest kind of failure to notice.
SERVE_CLIENT="${SERVE_CLIENT:-$(site_val SERVE_CLIENT)}"
case "$(printf '%s' "${SERVE_CLIENT:-yes}" | tr 'A-Z' 'a-z')" in
    no|0|false|off) SERVE_CLIENT=no ;;
    *)              SERVE_CLIENT=yes ;;
esac
CLIENT_PATH="${CLIENT_PATH:-$(site_val CLIENT_PATH)}"
[ -n "$CLIENT_PATH" ] || CLIENT_PATH=/client/

if [ "$SERVE_CLIENT" = no ]; then
    skip "this host does not serve the client bundle (SERVE_CLIENT=no)"
    info "an exported bundle is served elsewhere; build one with run.sh --client-export DIR"
else
    _cfail=0
    # The client scripts and bridges, plus the page and its runtime (app.js,
    # config.js). config.js is what carries the site values; a page without it
    # shows <set ... in config.js> markers, so its absence is a real failure.
    for _f in setup.sh setup.ps1 install-bridge.sh JsoncEdit.ps1 mcp-krb-bridge.py mcp-krb-remote-bridge.py mcp-fetch mcp-krb index.html app.js config.js; do
        _code="$(curl --proto '=https' --tlsv1.2 -sS --max-time 15                       -o /dev/null -w '%{http_code}'                       "https://$FQDN$CLIENT_PATH$_f" 2>/dev/null)"
        [ -n "$_code" ] || _code=000
        case "$_code" in
            200) pass "unauthenticated fetch of $CLIENT_PATH$_f -> 200" ;;
            401) fail "$CLIENT_PATH$_f returns 401: it sits behind the Kerberos gate"
                 info "a machine being provisioned holds no ticket, so this can never succeed"
                 _cfail=1 ;;
            *)   fail "$CLIENT_PATH$_f -> $_code"; _cfail=1 ;;
        esac
    done
    # The path itself must serve the page (index index.html), so a bare
    # https://host/client/ lands on the provisioning page rather than a 403/404.
    _idx="$(curl --proto '=https' --tlsv1.2 -sS --max-time 15 -o /dev/null -w '%{http_code}' "https://$FQDN$CLIENT_PATH" 2>/dev/null)"
    [ -n "$_idx" ] || _idx=000
    case "$_idx" in
        200) pass "unauthenticated fetch of $CLIENT_PATH (the page) -> 200" ;;
        *)   fail "$CLIENT_PATH (the page) -> $_idx: index index.html not serving"; _cfail=1 ;;
    esac
    [ "$_cfail" = 0 ] || info "re-run the installer to rebuild the bundle at $CLIENT_ROOT"
fi

# --------------------------------------------------------------------------
head2 "13. the running process is the deployed code"

# Catches the silent-stale-process class directly. `systemctl enable --now` does
# nothing to an already-running unit, so an installer that replaced the code in
# CODEDIR could leave yesterday's process serving it: unit active, every other
# check green, and the only symptom a newly added tool answering "Unknown tool".
# Compare when the process started against when the code was last written.
_code=/opt/mcp-server/mcp_server.py
_started="$(systemctl show mcp-server -p ActiveEnterTimestamp --value 2>/dev/null)"
if [ -f "$_code" ] && [ -n "$_started" ]; then
    _code_epoch="$(stat -c %Y "$_code" 2>/dev/null || echo 0)"
    _proc_epoch="$(date -d "$_started" +%s 2>/dev/null || echo 0)"
    if [ "$_proc_epoch" = 0 ] || [ "$_code_epoch" = 0 ]; then
        info "could not compare process start against code mtime on this system"
    elif [ "$_proc_epoch" -ge "$_code_epoch" ]; then
        pass "mcp-server started $(( (_proc_epoch - _code_epoch) / 60 ))m after $_code was written"
    else
        fail "mcp-server has been running since $_started, but $_code was written
       $(( (_code_epoch - _proc_epoch) / 60 )) minutes LATER. The process is serving STALE code."
        info "fix: systemctl restart mcp-server   (run.sh now restarts unconditionally)"
    fi
else
    info "no $_code or no unit timestamp; skipped"
fi

# --------------------------------------------------------------------------
head2 "14. on-behalf-of forwarding (SECURITY.md [D1])"

_unit=/etc/systemd/system/mcp-server.service
_deleg_on=0
grep -q '^Environment=MCP_DELEGATION=1' "$_unit" 2>/dev/null && _deleg_on=1
# Targets live in the policy document now, beside the groups, so read them
# from there rather than from the unit. Reading the unit would report "none"
# forever on a migrated host, and quietly vouch for a feature nobody checked.
_tgts="$(MCPPOL="$POLICY_FILE" python3 - <<'POLICYJSON' 2>/dev/null
import json, os
try:
    with open(os.environ['MCPPOL'], 'r', encoding='utf-8') as fh:
        doc = json.load(fh)
except Exception:
    raise SystemExit(0)
if isinstance(doc, dict):
    rows = ['%s=%s' % (t, v['forwards_to'])
            for t, v in sorted(doc.items())
            if isinstance(v, dict) and v.get('forwards_to')]
    if rows:
        print(','.join(rows))
POLICYJSON
)"

if [ "$_deleg_on" = 0 ]; then
    pass "forwarding is OFF (acceptor is receive-only; the keytab cannot authenticate outbound)"
    [ -n "$_tgts" ] && fail "but the policy grants targets ('$_tgts'), which reads as
       configured while nothing actually forwards"
else
    info "forwarding is ON: this keytab can authenticate OUTBOUND, which narrows [C2]"
    info "and raises what a stolen keytab is worth under [K1]"
    if [ -z "$_tgts" ]; then
        # Not a failure: half-enabled is a legitimate state, and a PASS here
        # would vouch for a feature that refuses every call it is asked to make.
        info "no forwards_to in the policy: every forward fails closed (no-target-policy)"
    else
        pass "targets: $_tgts"
        # Each target must be a principal the KDC actually knows, or the first real
        # call dies with a KDC error that reads like a delegation-rule problem.
        for _e in $(printf '%s' "$_tgts" | tr ',' ' '); do
            _spn="${_e#*=}"; _svc="${_spn%@*}"; _host="${_spn#*@}"
            if command -v ipa >/dev/null 2>&1 && klist -s 2>/dev/null; then
                if ipa service-show "$_svc/$_host" >/dev/null 2>&1; then
                    pass "  $_spn exists in IPA"
                else
                    fail "  $_spn is not a known IPA service principal"
                fi
            else
                info "  $_spn not checked (needs the ipa CLI and a ticket on this host)"
            fi
        done
        info "a caller who forwards a TGT is refused (credential-not-narrow-evidence),"
        info "so the realm's own servicedelegationtarget list constrains what is used"
    fi
fi

# --------------------------------------------------------------------------
printf '\n'
if [ "$FAILED" = 0 ]; then
    printf 'ALL CHECKS PASSED for %s\n' "$FQDN"
    exit 0
fi
printf '%s CHECK(S) FAILED for %s\n' "$FAILED" "$FQDN"
exit 1
