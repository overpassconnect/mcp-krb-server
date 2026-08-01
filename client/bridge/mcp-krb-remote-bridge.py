#!/usr/bin/env python3
"""The end of the pair that holds nothing.

THIS FILE CANNOT AUTHENTICATE ANYTHING. It imports no crypto, reads no keytab,
and touches no credential cache. That is its entire value, and it is worth
checking by reading it rather than taking on trust: the whole file is below.

"Remote" means the shared host you SSH into, from the workstation's point of
view. The name pairs with mcp-krb-bridge.py, which does hold your ticket, and
the symmetry is a little misleading on purpose-avoidance grounds: this one is
inert, and that is the point.

    workstation                        remote host (no ticket)
    -----------                        -----------------------
    mcp-krb-bridge.py --listen S   <-- ssh -R -->   this file
       holds the ticket                            moves bytes

Two modes, matching the two sockets the workstation serves:

    mcp-krb-remote-bridge.py SOCKET
        Join stdin/stdout to SOCKET. This is what an MCP client spawns; it sees
        an ordinary stdio server and never learns there is a network involved.

    mcp-krb-remote-bridge.py --fetch URL -o PATH [--sha256 HEX] --socket SOCKET
        Ask the workstation to fetch URL and stream the body back, then write it
        here. The GET happens over there, because the ticket is over there. The
        allowlist and every other restriction are enforced over there too, for
        the same reason: a caller on this end is exactly who those rules exist
        to constrain, so a copy of them here would be worth nothing.

A socket is not a credential. It cannot be copied off this machine or replayed
tomorrow, and it stops existing when the SSH session ends. What it does grant,
while the session is open, is the ability to act as the person who forwarded it,
so root here can use it. That is documented rather than hidden: see SECURITY.md.
"""
import argparse
import hashlib
import json
import os
import socket
import sys
import tempfile
import threading

BUF = 65536


def log(*a):
    print('[mcp-krb-remote-bridge]', *a, file=sys.stderr, flush=True)


def connect(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(path)
    except FileNotFoundError:
        sys.exit('%s does not exist. Is the ssh -R forward up? It is created by the '
                 'session that forwards it and disappears when that session ends.' % path)
    except (ConnectionRefusedError, OSError) as exc:
        sys.exit('%s exists but is not a live socket (%s). This is the normal look of '
                 'a stale socket from a previous session: the file outlives the '
                 'forward. Reconnect, or remove it.' % (path, exc.__class__.__name__))
    return s


def relay(path):
    """stdio <-> socket, until either side closes."""
    s = connect(path)

    def up():
        try:
            while True:
                b = sys.stdin.buffer.read1(BUF)
                if not b:
                    break
                s.sendall(b)
        except Exception:
            pass
        finally:
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threading.Thread(target=up, daemon=True).start()
    while True:
        b = s.recv(BUF)
        if not b:
            break
        sys.stdout.buffer.write(b)
        sys.stdout.buffer.flush()


def fetch(path, url, dest, sha256=None, force=False):
    """Ask the workstation for a URL; write the body here."""
    if os.path.exists(dest) and not force:
        sys.exit('%s exists; pass --force to overwrite' % dest)
    parent = os.path.dirname(os.path.abspath(dest)) or '.'
    if not os.path.isdir(parent):
        sys.exit('no such directory: %s' % parent)

    s = connect(path)
    s.sendall(json.dumps({'url': url}).encode('utf-8') + b'\n')

    # The wire is: one JSON line, then length-prefixed frames, then a zero
    # frame, then a JSON trailer. The digest cannot be known before the body
    # is sent, which is exactly why it arrives after it.
    buf = bytearray()

    def need(n):
        while len(buf) < n:
            chunk = s.recv(BUF)
            if not chunk:
                sys.exit('the workstation closed the connection mid-answer; '
                         'nothing was written')
            buf.extend(chunk)
        out = bytes(buf[:n])
        del buf[:n]
        return out

    def line():
        while b'\n' not in buf:
            chunk = s.recv(BUF)
            if not chunk:
                sys.exit('the workstation closed the connection without answering')
            buf.extend(chunk)
        i = buf.index(b'\n')
        out = bytes(buf[:i])
        del buf[:i + 1]
        return json.loads(out.decode('utf-8'))

    head = line()
    if not head.get('ok'):
        sys.exit('the workstation refused: %s' % head.get('error', 'unknown'))

    digest = hashlib.sha256()
    total = 0
    fd, tmp = tempfile.mkstemp(prefix='.mcp-fetch-', dir=parent)
    try:
        while True:
            n = int(need(10)[:8], 16)
            if n == 0:
                break
            chunk = need(n)
            total += n
            digest.update(chunk)
            os.write(fd, chunk)

        # The trailer is the only thing that authorises a rename. A stream that
        # stops early, or one the workstation gave up on, never reaches here.
        trailer = line()
        if not trailer.get('ok'):
            sys.exit('the workstation aborted: %s' % trailer.get('error', 'unknown'))

        got = digest.hexdigest()
        want = (sha256 or trailer.get('sha256') or '').lower().replace(':', '')
        if want and got != want:
            sys.exit('sha256 mismatch\n  expected %s\n  got      %s' % (want, got))
        if total != trailer.get('bytes', total):
            sys.exit('short read: expected %s bytes, got %d' % (trailer.get('bytes'), total))
        os.close(fd); fd = None
        os.replace(tmp, dest)         # only now does the file appear
        tmp = None
        log('wrote %s (%d bytes, sha256 %s)' % (dest, total, got))
    finally:
        if fd is not None:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        s.close()


def main():
    p = argparse.ArgumentParser(
        prog='mcp-krb-remote-bridge',
        description='Use a forwarded socket on a host that holds no Kerberos ticket.')
    p.add_argument('socket_path', nargs='?', help='the forwarded MCP socket')
    p.add_argument('--fetch', metavar='URL', help='ask the workstation to fetch this')
    p.add_argument('-o', '--output', metavar='PATH', help='destination for --fetch')
    p.add_argument('--sha256', metavar='HEX', help='expected digest')
    p.add_argument('--socket', metavar='PATH', dest='fetch_socket',
                   help='the forwarded fetch socket, for --fetch')
    p.add_argument('--force', action='store_true')
    o = p.parse_args()

    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, 'reconfigure'):
            try:
                stream.reconfigure(encoding='utf-8', newline='\n')
            except Exception:
                pass

    if o.fetch:
        if not o.output:
            p.error('--fetch needs -o PATH')
        if not o.fetch_socket:
            p.error('--fetch needs --socket PATH')
        fetch(o.fetch_socket, o.fetch, o.output, sha256=o.sha256, force=o.force)
        return

    if not o.socket_path:
        p.error('a socket path is required unless --fetch is used')
    relay(o.socket_path)


if __name__ == '__main__':
    main()
