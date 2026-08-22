#!/usr/bin/env python3
"""One-shot: fold MCP_DELEGATION_TARGETS into the policy file.

The policy document used to be {tool: "*" | [groups]}, and the forwarding
targets lived separately in the systemd unit as MCP_DELEGATION_TARGETS. They are
now one document:

    {tool: {"groups": "*" | [names], "forwards_to": "svc@fqdn"}}

Run this once, on the host, before starting the server with the new code. The
server does NOT accept the old shape, deliberately: a reader that took both
would let a file sit half-migrated and still load, which is how the two halves
drifted apart in the first place.

    sudo ./migrate-policy.py /var/lib/mcp-server/tool-groups.json \\
         --targets "$(systemctl show mcp-server -p Environment --value \\
                      | tr ' ' '\\n' | sed -n 's/^MCP_DELEGATION_TARGETS=//p')"

Idempotent: a document already in the new shape is left alone.

It writes through a temporary file in the same directory and renames, so an
interrupted run leaves the original intact rather than a half-written policy the
server would refuse at its next start.
"""
import argparse
import json
import os
import re
import sys
import tempfile

SPN_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}@[a-z0-9.-]{3,253}$')
TOOL_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')


def parse_targets(raw):
    """'tool=svc@fqdn,...' -> {tool: spn}. Same grammar the unit used."""
    out = {}
    for item in [x.strip() for x in (raw or '').split(',') if x.strip()]:
        tool, sep, spn = item.partition('=')
        tool, spn = tool.strip(), spn.strip()
        if not sep or not TOOL_RE.match(tool):
            raise SystemExit('bad targets entry %r, want tool=svc@fqdn' % item)
        if not SPN_RE.match(spn):
            raise SystemExit('bad SPN %r for tool %r' % (spn, tool))
        if tool in out:
            raise SystemExit('tool %r listed twice in targets' % tool)
        out[tool] = spn
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('policy', help='path to tool-groups.json')
    ap.add_argument('--targets', default='',
                    help='the old MCP_DELEGATION_TARGETS value')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    targets = parse_targets(args.targets)

    if not os.path.exists(args.policy):
        print('%s does not exist; nothing to migrate.' % args.policy)
        if targets:
            print('WARNING: %d target(s) were given but there is no policy file to '
                  'put them in. They would be lost. Create the policy first.'
                  % len(targets), file=sys.stderr)
            return 1
        return 0

    with open(args.policy, 'r', encoding='utf-8') as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise SystemExit('policy is not a JSON object')

    already = all(isinstance(v, dict) for v in doc.values()) and doc
    if already:
        missing = sorted(set(targets) - set(doc))
        if missing:
            raise SystemExit(
                'already in the new shape, but these targets name tools the policy '
                'does not list: %s. Refusing to guess.' % ', '.join(missing))
        print('%s is already in the new shape; nothing to do.' % args.policy)
        return 0

    out = {}
    for tool, val in sorted(doc.items()):
        if not isinstance(val, (str, list)):
            raise SystemExit('tool %s has an unexpected value %r' % (tool, val))
        rec = {'groups': val}
        if tool in targets:
            rec['forwards_to'] = targets[tool]
        out[tool] = rec

    orphans = sorted(set(targets) - set(out))
    if orphans:
        # A target for a tool with no policy entry never did anything: require()
        # denies the tool outright. Carrying it forward would preserve a grant
        # nothing consumes, waiting for a future tool of that name.
        raise SystemExit(
            'these tools have a forwarding target but no policy entry: %s. '
            'They cannot forward today either. Remove them from --targets, or '
            'add the tools first.' % ', '.join(orphans))

    canon = json.dumps(out, sort_keys=True, indent=2) + '\n'
    if args.dry_run:
        print(canon, end='')
        print('-- dry run, %s not written' % args.policy, file=sys.stderr)
        return 0

    d = os.path.dirname(os.path.abspath(args.policy)) or '.'
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.tool-groups.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(canon)
            fh.flush()
            os.fsync(fh.fileno())
        # Carry the original's mode and ownership across. The policy file is
        # mcp:mcp 0640 on a real host, and a migration that silently handed it to
        # root would leave the editor unable to save, which surfaces only when
        # somebody tries. chown is Linux-only, so this stays runnable (and
        # testable) on a workstation.
        st = os.stat(args.policy)
        os.chmod(tmp, st.st_mode & 0o7777)
        if hasattr(os, 'chown'):
            os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, args.policy)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

    print('migrated %d tool(s), %d with a forwarding target.'
          % (len(out), sum(1 for r in out.values() if 'forwards_to' in r)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
