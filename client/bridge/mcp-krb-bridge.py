#!/usr/bin/env python3
"""mcp-krb-bridge - stdio <-> Streamable-HTTP MCP bridge with Kerberos (SPNEGO) SSO.

Claude Code cannot speak HTTP Negotiate to a Kerberized MCP server; this bridge
can. Claude Code runs it as a plain stdio MCP server, and every JSON-RPC message
is forwarded to the remote endpoint with an `Authorization: Negotiate` header
minted from the Kerberos ticket the user already holds from logging in to a
FreeIPA-enrolled machine. No passwords, no API keys, no per-dev secrets.

Usage:
    mcp-krb-bridge https://mcp.example.internal/mcp [--ca /path/to/ca.pem]

Dependencies:
    Linux:   python3 + python3-gssapi (both already present on ipa-client machines)
    macOS:   python3 + `pip install gssapi` (the wheel links the system
             GSS.framework, the same Heimdal behind kinit, so both read one
             credential cache; nothing is bundled)
    Windows: python3 + `pip install pyspnego` (uses the native SSPI of the login session)

Environment:
    MCP_KRB_NOAUTH=1   skip the Authorization header entirely (local testing only)

Behavior notes:
  - A fresh SPNEGO token is minted per HTTP request (after the first request the
    HTTP/host service ticket is cached in the ccache, so this is local crypto,
    not a KDC round trip).
  - Streamable HTTP sessions (Mcp-Session-Id) are tracked; if the server loses
    the session (HTTP 404), the bridge transparently re-initializes and retries.
  - SSE-encoded POST responses are parsed and each event is forwarded, so
    progress notifications during long tool calls work.
  - Unsolicited server->client push (the standalone GET stream) is not opened;
    plain tool servers do not need it.
"""

import argparse
import base64
import json
import os
import ssl
import sys
import threading
import hashlib
import http.client
import re
import signal
import socket
import stat
import struct
import subprocess
import tempfile
from urllib.parse import urlsplit


def log(*parts):
    print('[mcp-krb-bridge]', *parts, file=sys.stderr, flush=True)


NOAUTH = os.environ.get('MCP_KRB_NOAUTH') == '1'

# --- Kerberos token minting -------------------------------------------------
if NOAUTH:
    def check_credentials():
        pass

    def negotiate_header(host):
        return None
else:
    try:
        import gssapi

        _SPNEGO_OID = gssapi.OID.from_int_seq('1.3.6.1.5.5.2')
        # Explicitly without delegate_to_peer: never forward the user's TGT to the
        # server, so a compromised server cannot impersonate the user onward. This
        # equals python-gssapi's safe default; stated explicitly for auditability.
        #
        # SECURITY.md [CL1], and this stopped being belt-and-braces the day
        # [D1] shipped. Enabling on-behalf-of forwarding requires workstation
        # tickets to be forwardable, and a forwardable ticket is exactly what a
        # client would need in order to hand over a TGT instead of the narrow
        # evidence credential.
        #
        # The server refuses a forwarded TGT (delegation.is_narrow_evidence), so
        # a client that did this would be denied rather than quietly widening
        # what the server can reach. That is the server's guarantee, not ours.
        # This list is how the shipped client stays on the right side of the line
        # in the first place: adding delegate_to_peer here would turn every user
        # of this bridge into the case the server has to reject. A test asserts
        # it is absent, in the declared flags and on the context actually built.
        _INIT_FLAGS = [gssapi.RequirementFlag.mutual_authentication,
                       gssapi.RequirementFlag.out_of_sequence_detection]

        def check_credentials():
            gssapi.Credentials(usage='initiate')

        def negotiate_header(host):
            name = gssapi.Name('HTTP@' + host, gssapi.NameType.hostbased_service)
            ctx = gssapi.SecurityContext(name=name, usage='initiate', mech=_SPNEGO_OID,
                                         flags=_INIT_FLAGS)
            return 'Negotiate ' + base64.b64encode(ctx.step()).decode()

    except ImportError:
        try:
            import spnego

            def check_credentials():
                pass  # SSPI draws from the interactive logon session

            def negotiate_header(host):
                ctx = spnego.client(hostname=host, service='HTTP')
                return 'Negotiate ' + base64.b64encode(ctx.step()).decode()

        except ImportError:
            log('missing Kerberos support: install python3-gssapi (Linux), '
                'run `pip install gssapi` (macOS), '
                'or `pip install pyspnego` (Windows)')
            sys.exit(2)


class Bridge:
    def __init__(self, url, cafile=None):
        u = urlsplit(url)
        if u.scheme not in ('http', 'https'):
            sys.exit('mcp-krb-bridge: URL must be http:// or https://')
        self.https = u.scheme == 'https'
        self.host = u.hostname
        if not self.https and self.host not in ('localhost', '127.0.0.1', '::1'):
            sys.exit('mcp-krb-bridge: refusing http:// to a non-local host. Use https://.')
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or '/'
        if u.query:
            self.path += '?' + u.query
        self.ssl_ctx = ssl.create_default_context(cafile=cafile) if self.https else None
        self.session_id = None
        self.protocol_version = None
        self.init_request = None        # raw initialize message, replayed if the session dies
        self.initialized_note = None    # raw notifications/initialized, replayed after re-init
        self.generation = 0             # bumped on every successful session recovery
        self.out_lock = threading.Lock()
        self.recover_lock = threading.Lock()

    # --- plumbing -----------------------------------------------------------

    def _connect(self):
        if self.https:
            return http.client.HTTPSConnection(self.host, self.port, context=self.ssl_ctx)
        return http.client.HTTPConnection(self.host, self.port)

    def _post(self, raw):
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
        }
        auth = negotiate_header(self.host)
        if auth:
            headers['Authorization'] = auth
        if self.session_id:
            headers['Mcp-Session-Id'] = self.session_id
        if self.protocol_version:
            headers['MCP-Protocol-Version'] = self.protocol_version
        conn = self._connect()
        conn.request('POST', self.path, body=raw.encode('utf-8'), headers=headers)
        return conn, conn.getresponse()

    def _emit(self, text):
        with self.out_lock:
            sys.stdout.write(text + '\n')
            sys.stdout.flush()

    def _emit_error(self, msg_id, message):
        if msg_id is None:
            log('error (notification, nothing to answer):', message)
            return
        self._emit(json.dumps({'jsonrpc': '2.0', 'id': msg_id,
                               'error': {'code': -32000, 'message': message}}))

    def _forward_body(self, body, emit):
        """Parse one JSON-RPC payload from the server; emit it as a single line."""
        try:
            obj = json.loads(body)
        except ValueError:
            log('dropping non-JSON payload from server:', body[:200])
            return
        # Sniff the negotiated protocol version off any initialize result.
        if isinstance(obj, dict):
            result = obj.get('result')
            if isinstance(result, dict) and 'protocolVersion' in result:
                self.protocol_version = result['protocolVersion']
        if emit:
            self._emit(json.dumps(obj, separators=(',', ':')))

    def _consume_sse(self, resp, emit):
        """Forward every `data:` event on an SSE response until the server closes it."""
        data_lines = []
        while True:
            line = resp.readline()
            if not line:
                break
            line = line.decode('utf-8', 'replace').rstrip('\r\n')
            if line == '':
                if data_lines:
                    self._forward_body('\n'.join(data_lines), emit)
                    data_lines = []
            elif line.startswith(':'):
                continue  # SSE keepalive comment
            elif line.startswith('data:'):
                chunk = line[5:]
                if chunk.startswith(' '):
                    chunk = chunk[1:]
                data_lines.append(chunk)
            # event:/id:/retry: fields carry nothing we need
        if data_lines:
            self._forward_body('\n'.join(data_lines), emit)

    def _read_response(self, resp, emit):
        ctype = (resp.getheader('Content-Type') or '').split(';')[0].strip().lower()
        if ctype == 'text/event-stream':
            self._consume_sse(resp, emit)
        else:
            body = resp.read().decode('utf-8', 'replace')
            if body.strip():
                self._forward_body(body, emit)

    # --- request lifecycle --------------------------------------------------

    def handle(self, raw):
        try:
            msg = json.loads(raw)
        except ValueError:
            log('dropping non-JSON stdin line:', raw[:200])
            return
        method = msg.get('method') if isinstance(msg, dict) else None
        msg_id = msg.get('id') if isinstance(msg, dict) else None
        if method == 'initialize':
            self.init_request = raw
        elif method == 'notifications/initialized':
            self.initialized_note = raw
        try:
            self._roundtrip(raw, msg_id, method)
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            log('transport error:', exc)
            self._emit_error(msg_id, 'bridge transport error: %s' % exc)
        except Exception as exc:  # gssapi/spnego failures land here
            log('error:', exc)
            self._emit_error(msg_id, 'bridge error: %s' % exc)

    def _roundtrip(self, raw, msg_id, method, allow_recover=True):
        generation = self.generation
        conn, resp = self._post(raw)
        try:
            sid = resp.getheader('Mcp-Session-Id')
            if sid:
                self.session_id = sid
            status = resp.status
            if status in (202, 204):
                resp.read()
                return
            if status == 404 and self.session_id and allow_recover and method != 'initialize':
                resp.read()
                log('session lost (HTTP 404) - re-initializing')
                self._recover_session(generation)
                self._roundtrip(raw, msg_id, method, allow_recover=False)
                return
            if status == 401:
                resp.read()
                hint = ('Kerberos authentication rejected (HTTP 401). Check `klist`; '
                        'if the ticket is missing or expired run `kinit` (or log in '
                        'again), then reconnect this MCP server.')
                log(hint)
                self._emit_error(msg_id, hint)
                return
            if status < 200 or status >= 300:
                body = resp.read().decode('utf-8', 'replace')[:300]
                self._emit_error(msg_id, 'HTTP %s from MCP server: %s' % (status, body))
                return
            self._read_response(resp, emit=True)
        finally:
            conn.close()

    def _recover_session(self, seen_generation):
        with self.recover_lock:
            if self.generation != seen_generation:
                return  # another thread already recovered the session
            if not self.init_request:
                raise RuntimeError('cannot recover session: no cached initialize request')
            self.session_id = None
            conn, resp = self._post(self.init_request)
            try:
                sid = resp.getheader('Mcp-Session-Id')
                if sid:
                    self.session_id = sid
                if resp.status != 200:
                    raise RuntimeError('re-initialize failed: HTTP %s' % resp.status)
                self._read_response(resp, emit=False)  # swallow: client already initialized
            finally:
                conn.close()
            if self.initialized_note:
                conn, resp = self._post(self.initialized_note)
                try:
                    resp.read()
                finally:
                    conn.close()
            self.generation += 1
            log('session re-established (%s)' % (self.session_id or 'stateless'))

    def close(self):
        """Best-effort session teardown on shutdown."""
        if not self.session_id:
            return
        try:
            headers = {'Mcp-Session-Id': self.session_id}
            auth = negotiate_header(self.host)
            if auth:
                headers['Authorization'] = auth
            conn = self._connect()
            conn.request('DELETE', self.path, headers=headers)
            conn.getresponse().read()
            conn.close()
        except Exception:
            pass



# ---------------------------------------------------------------------------
# Fetching a file, for content that must arrive byte-exact.
#
# An MCP tool cannot deliver such a file: every tool result is text bound for a
# context window, and a model reproducing a source file will occasionally
# reformat it or lose a trailing newline. Invisible in prose, a silent
# corruption in code. So the bytes are fetched here and never reach the model.
#
# Both the URL and the destination arrive from model output, so every default
# is restrictive. See SECURITY.md.
# ---------------------------------------------------------------------------

DEFAULT_MAX_BYTES = 8 * 1024 * 1024
_WINDOWS_PATH = re.compile(r'^[A-Za-z]:[\\/]')


class FetchRefused(Exception):
    """Policy said no. Exit 5, never write anything."""


def _realm_suffix():
    """Default host allowlist: the Kerberos realm, lowercased, as a domain."""
    try:
        with open('/etc/krb5.conf', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                if 'default_realm' in line and '=' in line:
                    return '.' + line.split('=', 1)[1].strip().lower()
    except OSError:
        pass
    return None


def _check_url(url, host_suffix):
    u = urlsplit(url)
    if u.scheme != 'https':
        raise FetchRefused('refusing %s:// - a Negotiate header in cleartext is '
                           'observable. Use https://.' % (u.scheme or 'empty'))
    if not u.hostname:
        raise FetchRefused('no host in URL')
    host = u.hostname.lower()
    if host_suffix and not (host == host_suffix.lstrip('.') or host.endswith(host_suffix)):
        raise FetchRefused('host %s is outside the allowed suffix %s. Pass '
                           '--allow-host-suffix to widen it deliberately.' % (host, host_suffix))
    return u


def _check_dest(dest, force, allow_outside):
    # A path shaped like C:\... reaches a WSL process as an ordinary relative
    # filename, colon and backslashes included, and creates a file by that
    # literal name while exiting 0. Refuse it rather than write nowhere.
    #
    # Only off native Windows, where such a path is simply correct. The hazard
    # is the WSL boundary, not the syntax, and refusing it on Windows would
    # reject every absolute path the platform has.
    if os.name != 'nt' and _WINDOWS_PATH.match(dest):
        raise FetchRefused('%s looks like a Windows path. Inside WSL that creates a '
                           'file named literally that, in the current directory. Use a '
                           'relative path, or translate it with `wslpath -u`.' % dest)
    parent = os.path.dirname(os.path.abspath(dest)) or '.'
    if not os.path.isdir(parent):
        raise FetchRefused('no such directory: %s' % parent)
    if not allow_outside:
        cwd = os.path.realpath(os.getcwd())
        real_parent = os.path.realpath(parent)
        if real_parent != cwd and not real_parent.startswith(cwd + os.sep):
            raise FetchRefused('%s is outside the working directory. Pass '
                               '--allow-outside if that is deliberate.' % dest)
    if os.path.islink(dest):
        raise FetchRefused('%s is a symlink; refusing to write through it' % dest)
    if os.path.isdir(dest):
        raise FetchRefused('%s is a directory' % dest)
    if os.path.exists(dest) and not force:
        raise FetchRefused('%s exists; pass --force to overwrite' % dest)
    return parent


def _open_response(url, cafile=None, host_suffix=None):
    """Policy, then one GET, then the status checks. Returns (conn, resp, path).

    Split out from fetch_to_file so that serving over a socket can stream the
    same single response instead of repeating the request. Fetching a URL twice
    to describe it once would make the digest a claim about a response nobody
    received."""
    u = _check_url(url, host_suffix)
    ctx = ssl.create_default_context(cafile=cafile)
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx)
    path = u.path or '/'
    if u.query:
        path += '?' + u.query
    headers = {'Accept': '*/*'}
    auth = negotiate_header(u.hostname)
    if auth:
        headers['Authorization'] = auth
    try:
        conn.request('GET', path, headers=headers)
        resp = conn.getresponse()

        # http.client does not follow redirects, and that immunity is
        # deliberate: forwarding an Authorization header across a cross-origin
        # redirect is a class with a long CVE history. Refuse rather than
        # reimplement it.
        if 300 <= resp.status < 400:
            raise FetchRefused('refusing to follow a %d redirect to %r. Fetch the '
                               'final URL directly.' % (resp.status, resp.getheader('Location')))
        if resp.status != 200:
            body = resp.read(512)
            raise RuntimeError('HTTP %d from %s%s: %s' % (resp.status, u.hostname, path,
                                                          body[:200].decode('utf-8', 'replace')))
    except Exception:
        conn.close()
        raise
    return conn, resp, path


def _stream(resp, sink, max_bytes, sha256=None):
    """Feed the body to sink in chunks. Returns (bytes, hexdigest).

    max_bytes is enforced here, as the bytes arrive, so every caller gets the
    cap whether it is writing a file or filling a socket."""
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise FetchRefused('response exceeds the %d byte limit' % max_bytes)
        digest.update(chunk)
        sink(chunk)
    got = digest.hexdigest()
    if sha256 and got != sha256.lower().replace(':', ''):
        raise ValueError('sha256 mismatch\n  expected %s\n  got      %s' % (sha256, got))
    return total, got


def fetch_to_file(url, dest, sha256=None, max_bytes=DEFAULT_MAX_BYTES,
                  force=False, allow_outside=False, cafile=None,
                  host_suffix=None):
    """SPNEGO GET of one URL, written to dest. Returns (bytes, hexdigest).

    Writes through a temporary file in the destination directory and renames
    only after the hash checks out, so "appears on disk" and "is complete" are
    the same event."""
    _check_url(url, host_suffix)                 # before a single packet moves
    parent = _check_dest(dest, force, allow_outside)
    conn, resp, _path = _open_response(url, cafile=cafile, host_suffix=host_suffix)

    tmp_fd, tmp_name = tempfile.mkstemp(prefix='.mcp-fetch-', dir=parent)
    try:
        total, got = _stream(resp, lambda b: os.write(tmp_fd, b), max_bytes, sha256)
        os.close(tmp_fd); tmp_fd = None
        os.replace(tmp_name, dest)      # atomic on POSIX and Windows
        tmp_name = None
        return total, got
    finally:
        if tmp_fd is not None:
            os.close(tmp_fd)
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        conn.close()


# ---------------------------------------------------------------------------
# Serving over a Unix socket, so a host with no ticket can use this one.
#
# The credential stays here. Only the channel is forwarded, by ssh -R. A socket
# is not a secret: it cannot be copied off a machine or replayed tomorrow, and
# it stops existing when the forward is torn down.
# ---------------------------------------------------------------------------

def _bind_socket(path):
    """Bind a 0600 Unix socket, clearing a stale one only if nothing answers."""
    if os.path.lexists(path):
        # Only ever remove a socket. A typo'd path that lands on a real file is
        # the likeliest way to reach this branch, and deleting it would be a
        # far worse answer than refusing.
        if not stat.S_ISSOCK(os.lstat(path).st_mode):
            sys.exit('mcp-krb-bridge: %s exists and is not a socket. Refusing to '
                     'remove it; choose another path.' % path)
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(path)
            probe.close()
            sys.exit('mcp-krb-bridge: %s is already served by another process' % path)
        except OSError:
            os.unlink(path)          # nothing behind it; a corpse from last time
        finally:
            try:
                probe.close()
            except OSError:
                pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o600)            # before a single connection is accepted
    srv.listen(8)
    return srv


def _peer_is_us(conn):
    """0600 should already prevent a stranger. Check anyway, so a permissions
    mistake fails closed instead of quietly opening the channel."""
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
        _pid, uid, _gid = struct.unpack('3i', creds)
        return uid == os.getuid()
    except (OSError, AttributeError):
        return True                  # not Linux; the mode is the control


def _serve(path, handler):
    srv = _bind_socket(path)
    log('listening on %s (0600)' % path)

    def cleanup(*_a):
        try:
            os.unlink(path)
        except OSError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    try:
        while True:
            conn, _ = srv.accept()
            if not _peer_is_us(conn):
                log('refused a connection from another uid')
                conn.close()
                continue
            threading.Thread(target=handler, args=(conn,), daemon=True).start()
    finally:
        cleanup()


def _pump(read, write, done):
    try:
        while True:
            b = read()
            if not b:
                break
            write(b)
    except Exception:
        pass
    finally:
        try:
            done()
        except Exception:
            pass


# --- git over the socket ----------------------------------------------------
#
# git cannot open a Unix socket and cannot mint a Negotiate header on a host that
# holds no ticket. What it can do is use an HTTP proxy: with http.proxy pointed
# at a loopback port, every request for an http:// remote arrives here in
# absolute-URI form, with the target host in the request line. So this end is a
# small authenticating proxy. It takes each request git makes, upgrades the
# scheme to https, adds a fresh Negotiate header minted from this workstation's
# ticket, forwards it to the real host, and streams the answer back. Clone,
# fetch and push are all GET and POST to git, so all three work, and git itself
# is untouched.
#
# The remote stays http:// on purpose. An https:// remote makes libcurl ask the
# proxy for a CONNECT tunnel, and nothing can be added inside a tunnel, so that
# is refused with an explanation rather than half-working. The cleartext leg is
# loopback into a Unix socket into an ssh channel; the wire to the real host is
# https from here.
#
# Every rule lives HERE, on the machine holding the ticket, for the same reason
# --fetch's do: the far end of a forwarded socket is exactly who the rules exist
# to constrain. The host must be in the realm, the upstream is always https,
# redirects are never followed, CONNECT is never honoured.

_HOP_BY_HOP = frozenset(('connection', 'keep-alive', 'proxy-connection',
                         'proxy-authorization', 'proxy-authenticate', 'te',
                         'trailer', 'upgrade'))


class _HttpReader:
    """Buffered reader over the accepted socket: header lines, then exact byte
    counts for a body. git reuses one connection for several requests, so the
    buffer has to survive across them."""

    def __init__(self, conn):
        self.conn = conn
        self.buf = bytearray()

    def line(self, limit=65536):
        while b'\r\n' not in self.buf:
            if len(self.buf) > limit:
                raise ValueError('header line too long')
            chunk = self.conn.recv(65536)
            if not chunk:
                return None
            self.buf.extend(chunk)
        i = self.buf.index(b'\r\n')
        out = bytes(self.buf[:i])
        del self.buf[:i + 2]
        return out

    def exactly(self, n):
        while len(self.buf) < n:
            chunk = self.conn.recv(65536)
            if not chunk:
                raise ValueError('client closed mid-body')
            self.buf.extend(chunk)
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out


def _git_read_head(rd):
    """Request line and headers. None at a clean EOF between requests."""
    line = rd.line()
    while line == b'':                  # a stray CRLF between keep-alive requests
        line = rd.line()
    if line is None:
        return None
    parts = line.decode('latin-1').split(' ')
    if len(parts) != 3:
        raise ValueError('malformed request line')
    method, target, _version = parts
    headers = []
    while True:
        h = rd.line()
        if h is None:
            raise ValueError('client closed inside the headers')
        if h == b'':
            break
        k, _, v = h.decode('latin-1').partition(':')
        headers.append((k.strip(), v.strip()))
    return method, target, headers


def _git_body(rd, hdr):
    """The request body exactly as git framed it, as an iterator of chunks, plus
    its length when the framing declares one (None when chunked)."""
    if 'chunked' in hdr.get('transfer-encoding', '').lower():
        def dechunk():
            while True:
                size = rd.line()
                if size is None:
                    raise ValueError('client closed inside a chunk size')
                n = int(size.split(b';')[0].strip() or b'0', 16)
                if n == 0:
                    while True:                       # optional trailers
                        t = rd.line()
                        if t is None or t == b'':
                            return
                yield rd.exactly(n)
                rd.exactly(2)                         # the CRLF after the chunk
        return dechunk(), None
    n = int(hdr.get('content-length', '0') or 0)

    def by_length():
        left = n
        while left > 0:
            piece = rd.exactly(min(left, 65536))
            left -= len(piece)
            yield piece
    return by_length(), n


def _git_reply(conn, status, reason, text):
    body = (text + '\n').encode('utf-8')
    conn.sendall(('HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n'
                  'Connection: close\r\n\r\n' % (status, reason, len(body))).encode('latin-1')
                 + body)


def _git_target(method, target, hdr):
    """(host, port, path) for the request, from the absolute-URI a proxy is given
    or, if a remote was pointed straight at the port, from the Host header."""
    if target.startswith('http://') or target.startswith('https://'):
        u = urlsplit(target)
        path = (u.path or '/') + ('?' + u.query if u.query else '')
        return u.hostname, u.port, path
    host = hdr.get('host', '').split(':')[0]
    return host, None, target


def _git_forward_one(rd, conn, cafile, host_suffix):
    """Serve one request from git. Returns False when the connection is done."""
    head = _git_read_head(rd)
    if head is None:
        return False
    method, target, headers = head
    hdr = {k.lower(): v for k, v in headers}

    if method == 'CONNECT':
        _git_reply(conn, 405, 'Method Not Allowed',
                   'krb-git proxies http:// remotes only. An https:// remote makes git ask '
                   'for a tunnel, and no ticket can be added inside one. krb-git maps a '
                   'realm host\'s https:// to http:// for you; if you see this, the remote '
                   'host is outside the realm or krb-git was bypassed.')
        return False

    host, port, path = _git_target(method, target, hdr)
    if not host:
        _git_reply(conn, 400, 'Bad Request', 'no target host in the request')
        return False
    try:
        _check_url('https://%s%s' % (host, path), host_suffix)     # realm-only, https
    except FetchRefused as exc:
        log('git: refused %s %s: %s' % (method, host, exc))
        _git_reply(conn, 403, 'Forbidden', str(exc))
        return False

    # git sends Expect: 100-continue ahead of a large POST and waits for it.
    if hdr.get('expect', '').lower() == '100-continue':
        conn.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')

    body, length = _git_body(rd, hdr)
    up_headers = {}
    for k, v in headers:
        kl = k.lower()
        # Framing is re-derived, Host is rewritten, and any Authorization git
        # was given is discarded: the ticket here is the only credential.
        if kl in _HOP_BY_HOP or kl in ('host', 'expect', 'authorization',
                                       'content-length', 'transfer-encoding'):
            continue
        up_headers[k] = v
    up_headers['Host'] = host if not port else '%s:%d' % (host, port)
    if length is not None:
        up_headers['Content-Length'] = str(length)
    auth = negotiate_header(host)
    if auth:
        up_headers['Authorization'] = auth

    ctx = ssl.create_default_context(cafile=cafile)
    up = http.client.HTTPSConnection(host, port or 443, context=ctx, timeout=600)
    try:
        if method in ('POST', 'PUT', 'PATCH'):
            payload = body
        else:
            for _ in body:                # keep the stream aligned
                pass
            payload = None
        # An iterable body with Content-Length is sent as-is; without one,
        # http.client chunks it, which is exactly the framing git used.
        up.request(method, path, body=payload, headers=up_headers)
        resp = up.getresponse()
        if 300 <= resp.status < 400:
            log('git: refusing to follow a %d redirect from %s' % (resp.status, host))
            _git_reply(conn, 502, 'Bad Gateway',
                       'the host redirected (%d); the proxy never follows one' % resp.status)
            return False
        log('git: %s %s%s -> %d' % (method, host, path.split('?', 1)[0], resp.status))

        # http.client has already undone the upstream framing, so the reply is
        # re-framed here: by length when the host declared one, chunked otherwise.
        # WWW-Authenticate is dropped so a 401 reads as final to git rather than
        # an invitation to try credentials it does not have.
        clen = None
        out = ['HTTP/1.1 %d %s' % (resp.status, resp.reason)]
        for k, v in resp.getheaders():
            kl = k.lower()
            if kl == 'content-length':
                clen = v
                continue
            if kl in _HOP_BY_HOP or kl in ('transfer-encoding', 'www-authenticate'):
                continue
            out.append('%s: %s' % (k, v))
        out.append('Content-Length: %s' % clen if clen is not None
                   else 'Transfer-Encoding: chunked')
        out.append('Connection: keep-alive')
        conn.sendall(('\r\n'.join(out) + '\r\n\r\n').encode('latin-1'))
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            conn.sendall(chunk if clen is not None
                         else b'%x\r\n' % len(chunk) + chunk + b'\r\n')
        if clen is None:
            conn.sendall(b'0\r\n\r\n')
    finally:
        up.close()
    return hdr.get('connection', '').lower() != 'close'


def serve_git_socket(path, cafile=None, host_suffix=None):
    """Each connection is one git session: requests are served in order on it
    until git closes, as any HTTP/1.1 proxy would."""
    def handle(conn):
        rd = _HttpReader(conn)
        try:
            while _git_forward_one(rd, conn, cafile, host_suffix):
                pass
        except Exception as exc:
            log('git: connection ended: %s' % exc)
        finally:
            try:
                conn.close()
            except OSError:
                pass
    _serve(path, handle)


def serve_mcp_socket(path, url, cafile=None):
    """Each connection gets its own bridge process, exactly as if it had been
    spawned on stdio. The remote end just moves bytes."""
    def handle(conn):
        p = subprocess.Popen([sys.executable, os.path.abspath(__file__), url]
                             + (['--ca', cafile] if cafile else []),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        threading.Thread(target=_pump,
                         args=(lambda: conn.recv(65536),
                               lambda b: (p.stdin.write(b), p.stdin.flush()),
                               p.stdin.close), daemon=True).start()
        _pump(lambda: p.stdout.read1(65536), conn.sendall, conn.close)
        p.wait()
    _serve(path, handle)


def serve_fetch_socket(path, cafile=None, host_suffix=None,
                       max_bytes=DEFAULT_MAX_BYTES):
    """One request per connection: a JSON line naming a URL, then the body.

    The restrictions are enforced HERE, on the machine holding the ticket. A
    caller on the far end of a forwarded socket is exactly who they would be
    protecting us from, so their copy of the rules would be worth nothing."""
    def handle(conn):
        streaming = False
        http_conn = None
        try:
            buf = b''
            while b'\n' not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
                if len(buf) > 8192:
                    raise FetchRefused('request line too long')
            req = json.loads(buf.split(b'\n', 1)[0].decode('utf-8'))
            url = str(req.get('url', ''))[:2048]
            # A caller may ask for a smaller cap than this one, never a larger:
            # the limit belongs to the machine holding the credential, and the
            # far end is who it exists to constrain.
            cap = max_bytes
            try:
                asked = int(req.get('max_bytes') or 0)
                if 0 < asked < cap:
                    cap = asked
            except (TypeError, ValueError):
                pass
            log('fetch request: %s' % url)

            # One GET. Everything that can be refused is refused before the
            # header line goes out, so a refusal is a clean "no" rather than a
            # truncated body.
            http_conn, resp, _p = _open_response(url, cafile=cafile,
                                                 host_suffix=host_suffix)
            conn.sendall(b'{"ok": true}\n')
            streaming = True
            total, got = _stream(resp, lambda b: conn.sendall(b'%08x\r\n' % len(b) + b),
                                 cap)
            conn.sendall(b'00000000\r\n' + json.dumps(
                {'ok': True, 'bytes': total, 'sha256': got}).encode() + b'\n')
        except Exception as exc:
            err = json.dumps({'ok': False, 'error': str(exc)[:400]}).encode() + b'\n'
            try:
                # Mid-stream, the failure has to reach the far end as a trailer,
                # because the header already promised a body. No trailer means
                # no file: the remote will not rename what it cannot confirm.
                conn.sendall((b'00000000\r\n' if streaming else b'') + err)
            except OSError:
                pass
        finally:
            for c in (http_conn, conn):
                try:
                    if c is not None:
                        c.close()
                except OSError:
                    pass
    _serve(path, handle)

def main():
    parser = argparse.ArgumentParser(
        prog='mcp-krb-bridge',
        description='stdio <-> Streamable-HTTP MCP bridge with Kerberos (SPNEGO) SSO')
    parser.add_argument('url', nargs='?',
                        help='remote MCP endpoint, e.g. https://mcp.internal.example/mcp')
    parser.add_argument('--ca', metavar='PEM', default=None,
                        help='trust only this CA bundle instead of the system store '
                             '(IPA-enrolled machines already trust the IPA CA system-wide)')

    # Fetch one file. For content that must arrive byte-exact, so it never
    # passes through a model.
    parser.add_argument('--fetch', metavar='URL', default=None,
                        help='fetch URL over SPNEGO and write it to -o, instead of '
                             'bridging stdio')
    parser.add_argument('-o', '--output', metavar='PATH', default=None,
                        help='destination for --fetch')
    parser.add_argument('--sha256', metavar='HEX', default=None,
                        help='verify the body before the file appears; a mismatch '
                             'leaves nothing behind')
    parser.add_argument('--max-bytes', type=int, default=DEFAULT_MAX_BYTES,
                        help='refuse a body larger than this (default %d)' % DEFAULT_MAX_BYTES)
    parser.add_argument('--force', action='store_true', help='overwrite an existing file')
    parser.add_argument('--allow-outside', action='store_true',
                        help='permit a destination outside the working directory')
    parser.add_argument('--allow-host-suffix', metavar='SUFFIX', default=None,
                        help='hosts allowed for --fetch (default: the Kerberos realm)')

    # Serve, so a machine with no ticket can use this one's.
    parser.add_argument('--listen', metavar='SOCKET', default=None,
                        help='serve MCP over a 0600 Unix socket instead of stdio, for '
                             'forwarding with ssh -R')
    parser.add_argument('--fetch-listen', metavar='SOCKET', default=None,
                        help='serve --fetch requests over a 0600 Unix socket')
    parser.add_argument('--git-listen', metavar='SOCKET', default=None,
                        help='serve git over a 0600 Unix socket, as an authenticating '
                             'HTTP proxy for a host that holds no ticket (krb-git)')
    opts = parser.parse_args()

    host_suffix = opts.allow_host_suffix or _realm_suffix()

    if opts.fetch:
        if not opts.output:
            parser.error('--fetch needs -o PATH')
        # Policy first, credentials second. A bad URL or a dangerous destination
        # is knowable without a ticket, and reporting "no Kerberos credentials"
        # for a refused destination sends people to fix the wrong thing.
        try:
            _check_url(opts.fetch, host_suffix)
            _check_dest(opts.output, opts.force, opts.allow_outside)
        except FetchRefused as exc:
            log('refused: %s' % exc)
            sys.exit(5)
        try:
            check_credentials()
        except Exception as exc:
            log('no usable Kerberos credentials: %s' % exc)
            sys.exit(2)
        try:
            n, got = fetch_to_file(opts.fetch, opts.output, sha256=opts.sha256,
                                   max_bytes=opts.max_bytes, force=opts.force,
                                   allow_outside=opts.allow_outside, cafile=opts.ca,
                                   host_suffix=host_suffix)
        except FetchRefused as exc:
            log('refused: %s' % exc); sys.exit(5)
        except ValueError as exc:
            log('%s' % exc); sys.exit(4)
        except Exception as exc:
            log('fetch failed: %s' % exc); sys.exit(3)
        log('wrote %s (%d bytes, sha256 %s)' % (opts.output, n, got))
        return

    if opts.fetch_listen:
        try:
            check_credentials()
        except Exception as exc:
            log('no usable Kerberos credentials: %s' % exc); sys.exit(2)
        serve_fetch_socket(opts.fetch_listen, cafile=opts.ca,
                           host_suffix=host_suffix, max_bytes=opts.max_bytes)
        return

    if opts.git_listen:
        try:
            check_credentials()
        except Exception as exc:
            log('no usable Kerberos credentials: %s' % exc); sys.exit(2)
        serve_git_socket(opts.git_listen, cafile=opts.ca, host_suffix=host_suffix)
        return

    if not opts.url:
        parser.error('a URL is required unless --fetch, --fetch-listen or --git-listen is used')

    if opts.listen:
        try:
            check_credentials()
        except Exception as exc:
            log('no usable Kerberos credentials: %s' % exc); sys.exit(2)
        serve_mcp_socket(opts.listen, opts.url, cafile=opts.ca)
        return

    # Keep pipes UTF-8 with plain \n on every platform (matters on Windows).
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, 'reconfigure'):
            try:
                stream.reconfigure(encoding='utf-8', newline='\n')
            except Exception:
                pass

    try:
        check_credentials()
    except Exception as exc:
        log('no usable Kerberos credentials - are you logged in to an IPA-enrolled '
            'machine? Run `klist`; if empty, `kinit`. Detail: %s' % exc)
        sys.exit(3)

    bridge = Bridge(opts.url, cafile=opts.ca)
    log('bridging stdio <-> %s%s' % (opts.url, ' (auth DISABLED)' if NOAUTH else ' with Kerberos SSO'))

    workers = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        t = threading.Thread(target=bridge.handle, args=(line,), daemon=True)
        t.start()
        workers.append(t)
        workers = [w for w in workers if w.is_alive()]

    for w in workers:
        w.join(timeout=10)
    bridge.close()


if __name__ == '__main__':
    main()
