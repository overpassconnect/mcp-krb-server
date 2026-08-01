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
        here. The GET happens over there, because the ticket is over there, and
        so does everything that decides whether a URL may be fetched at all: a
        caller on this end is exactly who those rules exist to constrain, so a
        copy of them here would be worth nothing.

        Where the file lands is the other way round. That is decided here,
        because the file is written here, so the destination checks are a real
        copy of the workstation's rather than a deferral to them.

A socket is not a credential. It cannot be copied off this machine or replayed
tomorrow, and it stops existing when the SSH session ends. What it does grant,
while the session is open, is the ability to act as the person who forwarded it,
so root here can use it. That is documented rather than hidden: see SECURITY.md.
"""
import argparse
import hashlib
import json
import os
import re
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


_WINDOWS_PATH = re.compile(r'^[A-Za-z]:[\\/]')


def check_dest(dest, force=False, allow_outside=False):
    """The same destination refusals mcp-krb-bridge.py applies.

    Deliberately a copy rather than an import: this file must stay standalone,
    since the module it would import from exits at load without a Kerberos
    stack, which a shared host has no reason to have. The copy is kept honest
    by a test that drives both implementations through the same cases.

    These are not about the network. They are about a path that arrived from
    model output, and that risk is identical on a shared host, which is why the
    checks cannot live only on the workstation: the file is written HERE.
    """
    if os.name != 'nt' and _WINDOWS_PATH.match(dest):
        sys.exit('%s looks like a Windows path. On this host that creates a file '
                 'named literally that, in the current directory. Use a relative '
                 'path, or translate it with `wslpath -u`.' % dest)
    parent = os.path.dirname(os.path.abspath(dest)) or '.'
    if not os.path.isdir(parent):
        sys.exit('no such directory: %s' % parent)
    if not allow_outside:
        cwd = os.path.realpath(os.getcwd())
        real_parent = os.path.realpath(parent)
        if real_parent != cwd and not real_parent.startswith(cwd + os.sep):
            sys.exit('%s is outside the working directory. Pass --allow-outside '
                     'if that is deliberate.' % dest)
    if os.path.islink(dest):
        sys.exit('%s is a symlink; refusing to write through it' % dest)
    if os.path.isdir(dest):
        sys.exit('%s is a directory' % dest)
    if os.path.exists(dest) and not force:
        sys.exit('%s exists; pass --force to overwrite' % dest)
    return parent


def fetch(path, url, dest, sha256=None, force=False, allow_outside=False,
          max_bytes=None):
    """Ask the workstation for a URL; write the body here."""
    parent = check_dest(dest, force=force, allow_outside=allow_outside)

    s = connect(path)
    req = {'url': url}
    # A cap asked for here can only lower the workstation's own. Raising it is
    # not on offer: the limit belongs to the machine holding the credential.
    if max_bytes:
        req['max_bytes'] = int(max_bytes)
    s.sendall(json.dumps(req).encode('utf-8') + b'\n')

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
    p.add_argument('--force', action='store_true', help='overwrite an existing file')
    # Accepted so that one mcp-fetch command line works on a workstation and on
    # a shared host alike. A flag that exists in one place and is an argparse
    # error in the other makes the wrapper's whole premise false.
    p.add_argument('--allow-outside', action='store_true',
                   help='permit a destination outside the working directory')
    p.add_argument('--max-bytes', type=int, default=None,
                   help='ask the workstation to cap the body below its own limit')
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
        fetch(o.fetch_socket, o.fetch, o.output, sha256=o.sha256, force=o.force,
              allow_outside=o.allow_outside, max_bytes=o.max_bytes)
        return

    if not o.socket_path:
        p.error('a socket path is required unless --fetch is used')
    relay(o.socket_path)


if __name__ == '__main__':
    main()
