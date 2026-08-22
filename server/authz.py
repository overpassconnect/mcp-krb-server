"""authz.py - security-owned authorization (keep this file under CODEOWNERS).

Per-tool access control by IPA group, plus the IPA group lookup. No MCP-SDK
dependency, so it is unit-testable on its own. Tool developers do not edit this
file; they add a tool to mcp_server.py and, with security review, one line here.

Model: each tool maps to the set of IPA groups whose members may call it. A user
may call a tool if they are in any of its groups (union). Deny by default: a tool
not listed here is denied. ANY_AUTHENTICATED opens a tool to every valid
principal. To change who can call a tool:
  - change IPA group membership in FreeIPA  (no code, no deploy - the common case), or
  - edit the tool's group set below         (code review + deploy - structural change).
"""
import hashlib
import json
import os
import re
import tempfile
import threading

# Set MCP_REALM for your site (e.g. MCP_REALM=CORP.EXAMPLE.COM). Hardcoding it
# here would make every deployment patch this file, and the value must match the
# SPN the acceptor was built with (MCP_SPN in mcp_server.py).
ALLOWED_REALM = '@' + os.environ.get('MCP_REALM', 'EXAMPLE.INTERNAL')

ANY_AUTHENTICATED = object()   # sentinel: any authenticated principal may call

# tool name -> {IPA group names} | ANY_AUTHENTICATED
TOOL_GROUPS = {
    'whoami':          ANY_AUTHENTICATED,
    'list_projects':   {'mcp-users'},
    'restart_service': {'mcp-operators'},
    'trigger_build':   {'mcp-operators'},
}


def authorize_connection(principal):
    """Coarse connection gate (before any tool). Refine if you want to require
    membership in an umbrella group here too."""
    return isinstance(principal, str) and principal.endswith(ALLOWED_REALM)


# --- IPA group lookup via nss/SSSD -----------------------------------------
# SSSD caches IPA group membership locally on this host, so os.getgrouplist is a
# fast local call with no per-request network. Fail closed (return empty, which
# denies) on any error. Platform-guarded so this module still imports where
# pwd/grp are absent (e.g. Windows CI running the hermetic tests).
_USER_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')

try:
    import pwd as _pwd
    import grp as _grp

    def _nss_groups(user):
        pw = _pwd.getpwnam(user)                        # nss -> SSSD
        gids = os.getgrouplist(user, pw.pw_gid)         # nss -> SSSD, no subprocess
        return {_grp.getgrgid(g).gr_name for g in gids}
except ImportError:
    def _nss_groups(user):
        raise RuntimeError('nss group lookup unavailable on this platform')


def ipa_groups(principal):
    """Set of IPA group names the principal belongs to (via SSSD). Fail-closed."""
    user = principal.split('@', 1)[0]
    if not _USER_RE.match(user):        # defensive: never feed junk to nss
        return set()
    try:
        return _nss_groups(user)
    except Exception:
        return set()                    # fail closed => authorization denies


def authorize_tool(principal, tool):
    """Return (allowed: bool, detail). detail is the matched group list when
    allowed, or a short reason string. Deny-by-default."""
    required = TOOL_GROUPS.get(tool)
    if required is None:
        return False, 'no-policy'
    if required is ANY_AUTHENTICATED:
        return True, 'any-authenticated'
    matched = sorted(ipa_groups(principal) & required)
    return bool(matched), (matched if matched else 'no-group')


# ==========================================================================
# Runtime policy overlay (only used by the optional, disabled-by-default admin
# editor - see authz_editor.py). The in-code TOOL_GROUPS above stays the
# authoritative fallback floor: an edited policy is always merged over it, so a
# missing, corrupt, or wiped policy file degrades to these reviewed defaults,
# never to "open". authz_editor is the only writer; nothing here reaches the
# network or executes data (JSON only, never Python), so the editor cannot be a
# code-injection path into this security-owned module.
# ==========================================================================

# Snapshot of the reviewed in-code default (taken once at import). Immutable
# reference used as the merge floor and the "reset to default" target.
_DEFAULT_TOOL_GROUPS = dict(TOOL_GROUPS)

# Reserved JSON encoding of the ANY_AUTHENTICATED sentinel (which has no JSON
# form). Chosen disjoint from any valid IPA posix group name (see _GROUP_RE), so
# a group can never be confused with "open to everyone".
ANY_TOKEN = '*'

_TOOL_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
_GROUP_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$')
# Hostbased SPN, 'svc@fqdn'. FQDNs only, never short names, so a target cannot be
# widened by whatever a resolver happens to answer.
_SPN_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}@[a-z0-9.-]{3,253}$')
_MAX_TOOLS = 512
_MAX_GROUPS_PER_TOOL = 64
_MAX_POLICY_BYTES = 256 * 1024

# tool -> frozenset({'svc@fqdn'}): the downstream service a tool may forward the
# caller's identity to. Deny by default; a tool absent here may not forward.
#
# It lives beside the groups because it answers the other half of one question.
# TOOL_GROUPS says who may call a tool; this says what that tool may then reach
# in their name. Splitting them across a systemd Environment= line and a JSON
# file meant the two halves had different homes, different lifetimes and no
# single place to read them, and a tool could sit in one and not the other with
# nothing to say so.
#
# It is deliberately NOT settable by register_tool_policy(). A tool declaring its
# own forwarding target is the caller-chosen-target hole wearing a different hat:
# the point of this map is that somebody other than the tool author decides.
TOOL_TARGETS = {}
_DEFAULT_TOOL_TARGETS = {}   # in-code defaults; this repo ships none

_policy_lock = threading.Lock()   # serialises validate + persist + rebind


def register_tool_policy(tool, groups):
    """Add a policy entry for a tool defined outside this file.

    A site extension (MCP_SITE_TOOLS, see mcp_server.py) adds tools that are not
    in the literal map above, and require() denies anything without an entry, so
    each one needs registering here.

    It writes the reviewed default as well as the live map. _apply() rebuilds the
    live map from _DEFAULT_TOOL_GROUPS every time a policy overlay is loaded, so
    an entry added only to the live map would vanish the first time the optional
    editor saved or reloaded, and the tool would start denying for no visible
    reason.

    What this does not do is widen anything by itself: a site tool still gets an
    explicit group set, chosen by whoever wrote the site file, and everything
    else in this module (deny by default, the realm gate, the SSSD lookup)
    applies unchanged. The CODEOWNERS gate on this file covers the mechanism; a
    deployment's own tool list is that deployment's to review."""
    if not isinstance(tool, str) or not _TOOL_RE.match(tool):
        raise ValueError('invalid tool name: %r' % (tool,))
    if groups is not ANY_AUTHENTICATED:
        if not groups or not all(isinstance(g, str) and _GROUP_RE.match(g) for g in groups):
            raise ValueError(
                'groups for %r must be ANY_AUTHENTICATED or a non-empty set of '
                'valid group names' % (tool,))
        if len(groups) > _MAX_GROUPS_PER_TOOL:
            raise ValueError('too many groups for %r' % (tool,))
        groups = frozenset(groups)
    with _policy_lock:
        if len(_DEFAULT_TOOL_GROUPS) >= _MAX_TOOLS and tool not in _DEFAULT_TOOL_GROUPS:
            raise ValueError('too many tools')
        _DEFAULT_TOOL_GROUPS[tool] = groups
        TOOL_GROUPS[tool] = groups



def policy_to_json(mapping=None, targets=None):
    """Canonical JSON-able view of the policy.

    {tool: {"groups": "*" | [names], "forwards_to": "svc@fqdn"}}, with
    forwards_to omitted entirely for a tool that may not forward, so the common
    case reads as an absence rather than a null."""
    m = TOOL_GROUPS if mapping is None else mapping
    t = TOOL_TARGETS if targets is None else targets
    out = {}
    for tool in sorted(m):
        v = m[tool]
        rec = {'groups': ANY_TOKEN if v is ANY_AUTHENTICATED else sorted(v)}
        spns = t.get(tool)
        if spns:
            # One target per tool. The set is an implementation detail of the
            # lookup, not something the document should invite widening.
            rec['forwards_to'] = sorted(spns)[0]
        out[tool] = rec
    return out


def policy_from_json(obj, known_tools=None):
    """Validate an untrusted JSON policy document and return a mapping
    {tool: ANY_AUTHENTICATED | frozenset(groups)}. Raises ValueError on any
    deviation (deny by default at the parser; never fail open). known_tools
    bounds the accepted tool names to the registered set (defaults to the
    in-code tools), so the editor cannot invent tools or smuggle unknown keys."""
    if not isinstance(obj, dict):
        raise ValueError('policy must be a JSON object')
    if len(obj) > _MAX_TOOLS:
        raise ValueError('too many tools')
    allowed = set(_DEFAULT_TOOL_GROUPS) if known_tools is None else set(known_tools)
    result = {}
    for tool, val in obj.items():
        if not isinstance(tool, str) or not _TOOL_RE.match(tool):
            raise ValueError('invalid tool name')
        if tool not in allowed:
            raise ValueError('unknown tool: ' + tool)
        if not isinstance(val, dict):
            raise ValueError(
                'each tool must map to an object with a "groups" key: %s. A bare '
                'group list is the old format and is not accepted; run '
                'server/install/migrate-policy.py once.' % tool)
        unknown = sorted(set(val) - {'groups', 'forwards_to'})
        if unknown:
            raise ValueError('unknown key(s) %s for tool %s' % (', '.join(unknown), tool))
        val = val.get('groups')
        if val == ANY_TOKEN:
            result[tool] = ANY_AUTHENTICATED
            continue
        if not isinstance(val, list) or not val:
            raise ValueError('groups must be "%s" or a non-empty array: %s' % (ANY_TOKEN, tool))
        if len(val) > _MAX_GROUPS_PER_TOOL:
            raise ValueError('too many groups: ' + tool)
        groups = set()
        for g in val:
            if not isinstance(g, str) or not _GROUP_RE.match(g):
                raise ValueError('invalid group name for tool ' + tool)
            groups.add(g)
        result[tool] = frozenset(groups)
    return result


def targets_from_json(obj, known_tools=None):
    """Validate the same document for forwarding targets and return
    {tool: frozenset({'svc@fqdn'})}. Absent forwards_to means the tool may not
    forward, which is the default and the common case.

    Separate from policy_from_json rather than folded into it because the two
    answer different questions with different blast radii: a wrong group denies
    somebody, a wrong target sends their identity somewhere it should not go.
    Both parse the same object, so neither can drift from the schema, and both
    refuse unknown keys."""
    if not isinstance(obj, dict):
        raise ValueError('policy must be a JSON object')
    allowed = set(_DEFAULT_TOOL_GROUPS) if known_tools is None else set(known_tools)
    out = {}
    for tool, val in obj.items():
        if not isinstance(tool, str) or not _TOOL_RE.match(tool):
            raise ValueError('invalid tool name')
        if tool not in allowed:
            raise ValueError('unknown tool: ' + tool)
        if not isinstance(val, dict):
            raise ValueError('each tool must map to an object: ' + tool)
        spn = val.get('forwards_to')
        if spn is None:
            continue
        if tool in _DEFAULT_TOOL_TARGETS:
            # A target written in code was reviewed there. Letting a document
            # redirect it silently is the whole failure this map exists to stop,
            # so a collision is fatal rather than resolved by precedence.
            raise ValueError(
                'forwards_to for %s is set in code; a policy document may not '
                'redirect a reviewed target' % tool)
        if not isinstance(spn, str) or not _SPN_RE.match(spn):
            raise ValueError(
                'forwards_to for %s must be svc@fqdn with a fully qualified host, '
                'not %r' % (tool, spn))
        out[tool] = frozenset({spn})
    return out


def policy_etag(mapping=None):
    """A strong, quoted HTTP ETag over the canonical policy (for If-Match)."""
    canon = json.dumps(policy_to_json(mapping), sort_keys=True, separators=(',', ':'))
    return '"' + hashlib.sha256(canon.encode('utf-8')).hexdigest()[:32] + '"'


def _apply(overlay, targets=None):
    """Build effective policy = defaults with the validated overlay merged over,
    and atomically rebind the module globals (a name rebind is atomic under the
    GIL; in-flight callers keep the value they already captured). Caller must
    hold _policy_lock. Never mutates the live dicts in place.

    Groups and targets rebind in one call, from one document, so a tool can never
    be live with one half of its policy and a stale other half."""
    global TOOL_GROUPS, TOOL_TARGETS
    merged = dict(_DEFAULT_TOOL_GROUPS)
    merged.update(overlay)
    TOOL_GROUPS = merged
    merged_t = dict(_DEFAULT_TOOL_TARGETS)
    merged_t.update(targets or {})
    TOOL_TARGETS = merged_t


def reset_policy():
    """Drop any overlay: revert the live policy to the reviewed in-code default."""
    with _policy_lock:
        _apply({})


def load_policy_file(path, known_tools=None):
    """Load + validate the on-disk overlay and apply it. Fails closed: on any
    read/parse/validation error keep the current policy and return (False,
    reason); never fall back to open. A missing file is success (pure defaults)."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            raw = f.read(_MAX_POLICY_BYTES + 1)
    except FileNotFoundError:
        with _policy_lock:
            _apply({})
        return True, None
    except OSError:
        return False, 'read-error'
    if len(raw) > _MAX_POLICY_BYTES:
        return False, 'too-large'
    try:
        doc = json.loads(raw)
        overlay = policy_from_json(doc, known_tools=known_tools)
        targets = targets_from_json(doc, known_tools=known_tools)
    except (ValueError, RecursionError) as e:
        return False, 'invalid:' + str(e)
    with _policy_lock:
        _apply(overlay, targets)
    return True, None


def write_policy(path, obj, known_tools=None):
    """Validate the untrusted JSON doc, persist atomically (tmp in the same dir +
    fsync + os.replace), then apply. Returns the new ETag. Raises ValueError on
    invalid input (before any disk write) or OSError on a persistence failure;
    in both cases the live policy is unchanged."""
    overlay = policy_from_json(obj, known_tools=known_tools)    # validate first
    targets = targets_from_json(obj, known_tools=known_tools)   # both, or neither
    canon = json.dumps(policy_to_json(overlay, targets), sort_keys=True, indent=2) + '\n'
    with _policy_lock:
        d = os.path.dirname(path) or '.'
        fd, tmp = tempfile.mkstemp(dir=d, prefix='.tool-groups.', suffix='.tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(canon)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o640)
            os.replace(tmp, path)          # atomic swap; readers never see a partial file
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        _apply(overlay, targets)
        return policy_etag()
