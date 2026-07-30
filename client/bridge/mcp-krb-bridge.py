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
import http.client
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


def main():
    parser = argparse.ArgumentParser(
        prog='mcp-krb-bridge',
        description='stdio <-> Streamable-HTTP MCP bridge with Kerberos (SPNEGO) SSO')
    parser.add_argument('url', help='remote MCP endpoint, e.g. https://mcp.internal.example/mcp')
    parser.add_argument('--ca', metavar='PEM', default=None,
                        help='trust only this CA bundle instead of the system store '
                             '(IPA-enrolled machines already trust the IPA CA system-wide)')
    opts = parser.parse_args()

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
