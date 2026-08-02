"""authz_editor.py - optional, disabled-by-default admin editor for the per-tool
IPA-group policy (authz.TOOL_GROUPS). Security-owned; keep under CODEOWNERS.

Design (see ../SECURITY.md [S4-EDITOR]):

  * Disabled by default. build_editor() returns None unless MCP_AUTHZ_EDITOR is
    truthy and a non-empty, well-formed policy-admin allowlist is configured.
    When disabled the routes do not exist, rather than merely returning 403: the
    dispatcher is never installed, so the running server is byte-for-byte the
    same as before.

  * Reuses the proven auth path. It sits behind SpnegoAuthMiddleware, so every
    request is already Kerberos-authenticated (the [C1] completeness gate, mech
    pin, principal validation) and the caller principal is on the ASGI scope. It
    adds no new authentication code.

  * The editor's own gate is a code/config-pinned principal allowlist, kept
    separate from the mutable TOOL_GROUPS it edits. So an edit can never open the
    editor to others, add a policy-admin, or lock the admins out of the editor.
    It is deliberately not an IPA group (an IPA/KDC compromise must not mint a
    policy-admin), and not the generic admin@REALM.

  * Ambient-credential CSRF defense (Negotiate is ambient like a cookie): the
    state-changing PUT requires an exact same-origin Origin (fail-closed),
    Sec-Fetch-Site==same-origin when present, a strict application/json
    Content-Type checked from the header before the body is read, and a matching
    If-Match ETag. There is no GET/simple-request route to the mutation and the
    server emits no permissive CORS.

  * Persists data, never code: writes a validated JSON overlay file (authz.write_
    policy: schema-validated, atomic, fail-safe to last-good), never rewrites
    authz.py. The HTML is returned in-memory (no FileResponse) under a per-
    response nonce CSP.
"""
import asyncio
import base64
import html
import json
import os

import authz

# Must match spnego_asgi.SCOPE_PRINCIPAL. Duplicated (not imported) so this
# module stays free of the gssapi dependency and is unit-testable on its own.
SCOPE_PRINCIPAL = 'krb_principal'

PATH_HTML = '/admin/authz'
PATH_API = '/admin/authz.json'
ADMIN_PREFIX = '/admin/'

_MAX_BODY = 64 * 1024   # policy blobs are a few KB; nginx caps too, this is belt

# Sentinels returned by _read_body. Distinct objects rather than None so a client
# that legitimately sends an empty body is not confused with a failure.
_BODY_TOO_LARGE = object()
_BODY_DISCONNECTED = object()

# An ASGI http receive() only ever yields 'http.request' or 'http.disconnect'.
# Anything else is skipped, but only a bounded number of times: an unbounded
# `continue` on an unexpected message is how a receive() that never blocks turns
# into a busy loop that pins the single event loop for every other user.
_MAX_UNEXPECTED_MESSAGES = 64


def _principals_from_env(raw):
    """Parse MCP_POLICY_ADMINS (comma-separated) into a validated frozenset of
    full principals. Anything that is not a well-formed realm principal is
    dropped (fail-closed), so a typo cannot silently widen access."""
    admins = set()
    for p in (raw or '').split(','):
        p = p.strip()
        if p and authz.authorize_connection(p):   # exact realm-pinned, str only
            admins.add(p)
    return frozenset(admins)


def build_editor(audit):
    """Return a configured AuthzEditorApp, or None if the editor is disabled
    (the default). Fails CLOSED: enabling with no valid policy-admins logs a
    warning and stays disabled. When enabled, loads the on-disk policy overlay
    (fail-closed) so a bad file never opens the policy."""
    if os.environ.get('MCP_AUTHZ_EDITOR', '').strip().lower() not in ('1', 'true', 'yes', 'on'):
        return None
    admins = _principals_from_env(os.environ.get('MCP_POLICY_ADMINS', ''))
    if not admins:
        audit({'event': 'authz_editor.disabled', 'reason': 'no-valid-policy-admins'})
        return None
    policy_file = os.environ.get('MCP_POLICY_FILE', '/var/lib/mcp-server/tool-groups.json')
    public_origin = os.environ.get('MCP_PUBLIC_ORIGIN', 'https://mcp.example.internal')
    known_tools = frozenset(authz._DEFAULT_TOOL_GROUPS)
    ok, reason = authz.load_policy_file(policy_file, known_tools=known_tools)
    audit({'event': 'authz_editor.enabled', 'policyFile': policy_file, 'admins': sorted(admins),
           'origin': public_origin, 'policyLoaded': ok, 'loadDetail': reason})
    return AuthzEditorApp(policy_file, public_origin, admins, audit, known_tools)


class Dispatch:
    """Route /admin/* HTTP requests to the editor, everything else (and every
    non-http scope: lifespan/websocket) to the wrapped MCP app so its session-
    manager lifespan still starts. Installed only when the editor is enabled."""

    def __init__(self, default_app, admin_app):
        self.default_app = default_app
        self.admin_app = admin_app

    async def __call__(self, scope, receive, send):
        if scope.get('type') == 'http' and scope.get('path', '').startswith(ADMIN_PREFIX):
            await self.admin_app(scope, receive, send)
        else:
            await self.default_app(scope, receive, send)


class AuthzEditorApp:
    def __init__(self, policy_file, public_origin, admins, audit, known_tools):
        self.policy_file = policy_file
        self.public_origin = public_origin
        self.admins = admins
        self.audit = audit
        self.known_tools = known_tools
        # Serialises the If-Match re-check with the write that depends on it.
        # Without it the check and the write are separated by awaits, two
        # concurrent admin edits both pass the check and the second silently
        # discards the first. authz._policy_lock cannot be used for this: it is
        # a non-reentrant threading.Lock taken inside authz.write_policy, so
        # holding it around the call would deadlock. This editor is the only
        # writer of the policy, so serialising here is sufficient.
        self._write_lock = asyncio.Lock()

    async def __call__(self, scope, receive, send):
        # scope is guaranteed http and already Kerberos-authenticated upstream.
        principal = scope.get(SCOPE_PRINCIPAL)
        method = scope.get('method', '')
        path = scope.get('path', '')
        headers = {k.lower(): v for k, v in (scope.get('headers') or [])}
        client_ip = self._client_ip(scope, headers)

        # Editor's own gate: code/config-pinned allowlist, separate from TOOL_GROUPS.
        if not principal or principal not in self.admins:
            self.audit({'event': 'authz_editor.access', 'allowed': False, 'reason': 'not-policy-admin',
                        'principal': principal, 'clientIp': client_ip, 'method': method, 'path': path})
            return await self._json(send, 403, {'error': 'forbidden'})

        if path == PATH_HTML and method == 'GET':
            return await self._page(send, principal)
        if path == PATH_API and method == 'GET':
            return await self._get_policy(send)
        if path == PATH_API and method == 'PUT':
            return await self._put_policy(scope, receive, send, principal, headers, client_ip)
        if path in (PATH_HTML, PATH_API):
            return await self._json(send, 405, {'error': 'method-not-allowed'},
                                    extra=[(b'allow', b'GET, PUT' if path == PATH_API else b'GET')])
        return await self._json(send, 404, {'error': 'not-found'})

    # --- reads -------------------------------------------------------------
    async def _get_policy(self, send):
        body = {'policy': authz.policy_to_json(), 'etag': authz.policy_etag(),
                'defaults': authz.policy_to_json(authz._DEFAULT_TOOL_GROUPS),
                'tools': sorted(self.known_tools), 'anyToken': authz.ANY_TOKEN}
        return await self._json(send, 200, body, extra=[(b'etag', authz.policy_etag().encode())])

    async def _page(self, send, principal):
        nonce = base64.b64encode(os.urandom(16)).decode('ascii')
        page = _HTML.replace('%NONCE%', nonce) \
                    .replace('%API%', html.escape(PATH_API)) \
                    .replace('%PRINCIPAL%', html.escape(principal)) \
                    .replace('%ORIGIN%', html.escape(self.public_origin)) \
                    .replace('%ANYTOKEN%', html.escape(authz.ANY_TOKEN))
        csp = ("default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; "
               "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'") % (nonce, nonce)
        hdrs = [(b'content-type', b'text/html; charset=utf-8'),
                (b'content-security-policy', csp.encode('ascii')),
                (b'x-content-type-options', b'nosniff'),
                (b'cache-control', b'no-store'),
                (b'referrer-policy', b'no-referrer')]
        await send({'type': 'http.response.start', 'status': 200, 'headers': hdrs})
        await send({'type': 'http.response.body', 'body': page.encode('utf-8')})

    # --- write (the sensitive path) ---------------------------------------
    async def _put_policy(self, scope, receive, send, principal, headers, client_ip):
        def deny(code, reason):
            self.audit({'event': 'authz_editor.write', 'allowed': False, 'reason': reason,
                        'principal': principal, 'clientIp': client_ip})
            return self._json(send, code, {'error': reason})

        # 1) Ambient-credential CSRF gate (Negotiate is ambient; fail-closed).
        origin = headers.get(b'origin', b'').decode('latin-1')
        if origin != self.public_origin:                       # exact; missing/'null' -> reject
            return await deny(403, 'bad-origin')
        sfs = headers.get(b'sec-fetch-site', b'').decode('latin-1')
        if sfs and sfs != 'same-origin':                       # browsers always send it
            return await deny(403, 'cross-site')

        # 2) Strict media type, checked from the header before reading the body;
        #    a JSON parser that ignores Content-Type is not a substitute.
        ctype = headers.get(b'content-type', b'').decode('latin-1').split(';')[0].strip().lower()
        if ctype != 'application/json':
            return await deny(415, 'unsupported-media-type')

        # 3) Optimistic concurrency: require an If-Match (no '*', no blank). This
        #    first comparison is only a cheap early reject so an already-stale
        #    request is refused before its body is read. It is not the decision:
        #    the binding check is repeated under _write_lock below, because a
        #    check made here and a write made after an await is not atomic.
        inm = headers.get(b'if-match', b'').decode('latin-1').strip()
        if not inm:
            return await deny(428, 'precondition-required')
        current = authz.policy_etag()
        if inm != current:
            return await self._json(send, 412, {'error': 'etag-mismatch', 'etag': current},
                                    extra=[(b'etag', current.encode())])

        # 4) Bounded read + parse.
        body = await self._read_body(receive)
        if body is _BODY_DISCONNECTED:
            # Client is gone; no response can be delivered. Nothing was written.
            self.audit({'event': 'authz_editor.write', 'allowed': False, 'reason': 'client-disconnected',
                        'principal': principal, 'clientIp': client_ip})
            return
        if body is _BODY_TOO_LARGE:
            return await deny(413, 'too-large')
        try:
            obj = json.loads(body)
        except (ValueError, RecursionError):
            return await deny(400, 'invalid-json')

        # 5) Re-check the precondition and write while holding _write_lock, so
        #    the pair is atomic and the last-writer-wins loss is impossible.
        #    Everything between the read above and the write below is a single
        #    lock hold with no await on the client, and this editor is the only
        #    writer of the policy, so a concurrent edit can only be observed here
        #    as a changed ETag and is answered 412 instead of being overwritten.
        #    No I/O to the client happens inside the lock: the outcome is decided
        #    there and only rendered afterwards, so a slow socket cannot hold the
        #    policy lock.
        outcome = None
        async with self._write_lock:
            current = authz.policy_etag()
            if inm != current:
                outcome = ('stale', current)
            else:
                before = authz.policy_to_json()
                try:
                    new_etag = authz.write_policy(self.policy_file, obj, known_tools=self.known_tools)
                except ValueError as e:
                    outcome = ('invalid', 'invalid-policy:' + str(e))
                except OSError:
                    outcome = ('oserror', 'persist-failed')
                else:
                    outcome = ('ok', new_etag, before, authz.policy_to_json())

        if outcome[0] == 'stale':
            current = outcome[1]
            return await self._json(send, 412, {'error': 'etag-mismatch', 'etag': current},
                                    extra=[(b'etag', current.encode())])
        if outcome[0] == 'invalid':
            return await deny(400, outcome[1])
        if outcome[0] == 'oserror':
            return await deny(500, outcome[1])
        _, new_etag, before, after = outcome
        self.audit({'event': 'policy.change', 'principal': principal, 'clientIp': client_ip,
                    'before': before, 'after': after})
        return await self._json(send, 200, {'ok': True, 'etag': new_etag, 'policy': after},
                                extra=[(b'etag', new_etag.encode())])

    # --- helpers -----------------------------------------------------------
    async def _read_body(self, receive):
        """Read a bounded request body.

        Returns the bytes, or _BODY_TOO_LARGE, or _BODY_DISCONNECTED.

        Termination is the point of this function. A client that passes the
        Origin/Content-Type/If-Match gates and then hangs up mid-body makes the
        server's receive() return {'type': 'http.disconnect'} immediately and
        forever. Treating that as "not my message, keep going" spins this
        coroutine at 100% CPU on the single asyncio loop, permanently, for every
        user of the process - a total loss of service reachable without a write
        ever being authorised. So: disconnect ends the read, and every other
        unexpected message type is skipped only a bounded number of times.
        """
        chunks, total, skipped = [], 0, 0
        while True:
            msg = await receive()
            mtype = msg.get('type')
            if mtype == 'http.disconnect':
                return _BODY_DISCONNECTED
            if mtype != 'http.request':
                skipped += 1
                if skipped > _MAX_UNEXPECTED_MESSAGES:
                    return _BODY_DISCONNECTED
                continue
            part = msg.get('body', b'') or b''
            total += len(part)
            if total > _MAX_BODY:
                return _BODY_TOO_LARGE
            chunks.append(part)
            if not msg.get('more_body'):
                break
        return b''.join(chunks)

    async def _json(self, send, status, obj, extra=None):
        body = json.dumps(obj).encode('utf-8')
        hdrs = [(b'content-type', b'application/json'), (b'cache-control', b'no-store'),
                (b'x-content-type-options', b'nosniff')]
        if extra:
            hdrs.extend(extra)
        await send({'type': 'http.response.start', 'status': status, 'headers': hdrs})
        await send({'type': 'http.response.body', 'body': body})

    def _client_ip(self, scope, headers):
        xff = headers.get(b'x-forwarded-for')
        if xff:
            return xff.decode('latin-1')
        client = scope.get('client')
        return client[0] if client else '?'


# Minimal same-origin page. All script/style are nonce'd so it runs under a tight
# CSP (default-src 'none'). It fetches the current policy + ETag, lets the admin
# edit the JSON, and PUTs it back with If-Match. No external assets, no inline
# handlers, no framework.
#
# A RAW string, and it has to stay one. The JS below uses backslash escapes in
# regexes and in string literals. Without the r-prefix Python consumes them
# first: a backslash-n inside a JS string becomes a real newline, which is a JS
# syntax error, and a doubled backslash in the token regex collapses to a single
# one, which is a different and wrong pattern. Neither shows up until the page
# is loaded in a browser. Nothing in this template needs Python-level escapes.
_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP authz policy editor</title>
<style nonce="%NONCE%">
  body { font: 14px/1.5 system-ui, sans-serif; max-width: 820px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.25rem; }
  .meta { color: #555; font-size: 12px; margin-bottom: 1rem; }
  button { font-size: 14px; padding: 6px 14px; margin-right: 8px; }
  #status { margin-top: 10px; white-space: pre-wrap; font-family: ui-monospace, monospace; }
  .ok { color: #137333; } .err { color: #b00020; }
  code { background: #f2f2f2; padding: 1px 4px; }

  /* The textarea sits transparent on top of a <pre> holding the coloured copy.
     A textarea cannot be styled per-token, and pulling in an editor component
     to colour five token types is not a trade worth making here.

     Every metric below has to match in both layers or the caret drifts from
     the glyphs, which is why they share one rule and why wrapping is off:
     soft wrap in a textarea is not reproducible in a <pre> without guessing at
     the same break points. */
  /* Scales with the window rather than sitting at a fixed height: the policy
     grows a line per tool, and a box that fits one screen is a scrollbar on
     the next. The floor keeps it usable on a laptop, the ceiling stops a tall
     monitor from putting the buttons somewhere you have to hunt for them. */
  .editor { position: relative; height: clamp(340px, 68vh, 1000px); }
  .editor > * {
    position: absolute; inset: 0; margin: 0; width: 100%; height: 100%;
    box-sizing: border-box; padding: 6px; border: 1px solid #767676;
    font: 13px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace;
    white-space: pre; overflow: auto; tab-size: 2;
  }
  #hl { pointer-events: none; z-index: 0; background: #fff; color: #24292f; }
  #policy {
    z-index: 1; resize: none; background: transparent;
    color: transparent; caret-color: #24292f;
  }
  #policy::selection { background: #b3d7ff; }
  .k { color: #0550ae; }          /* object key      */
  .s { color: #0a7c3e; }          /* string value    */
  .n { color: #953800; }          /* number          */
  .l { color: #8250df; }          /* true false null */
  #valid { min-height: 1.2em; margin-top: 6px; font-family: ui-monospace, monospace; font-size: 12px; }

  @media (prefers-color-scheme: dark) {
    body { background: #0d1117; color: #c9d1d9; }
    .meta { color: #8b949e; } code { background: #21262d; }
    .editor > * { border-color: #30363d; }
    #hl { background: #0d1117; color: #c9d1d9; }
    #policy { caret-color: #c9d1d9; }
    .k { color: #79c0ff; } .s { color: #7ee787; }
    .n { color: #ffa657; } .l { color: #d2a8ff; }
    .ok { color: #3fb950; } .err { color: #ff7b72; }
  }
</style>
</head>
<body>
<h1>Per-tool IPA-group policy</h1>
<div class="meta">
  Signed in as <code>%PRINCIPAL%</code> &middot; origin <code>%ORIGIN%</code><br>
  Each tool maps to a JSON array of IPA group names (member of ANY grants access),
  or <code>"%ANYTOKEN%"</code> for any authenticated principal. Only registered
  tools are accepted; omitted tools keep their reviewed code default.
</div>
<div class="editor">
  <pre id="hl" aria-hidden="true"></pre>
  <textarea id="policy" spellcheck="false" wrap="off" autocapitalize="off"
            autocomplete="off" autocorrect="off" aria-label="policy JSON"></textarea>
</div>
<div id="valid" aria-live="polite"></div>
<div style="margin-top:10px">
  <button id="save" type="button">Save</button>
  <button id="reload" type="button">Reload</button>
</div>
<div id="status"></div>
<script nonce="%NONCE%">
(function () {
  var API = "%API%";
  var etag = null;
  var ta = document.getElementById("policy");
  var hl = document.getElementById("hl");
  var validEl = document.getElementById("valid");
  var statusEl = document.getElementById("status");
  function show(msg, cls) { statusEl.textContent = msg; statusEl.className = cls || ""; }

  // JSON has five token types and no ambiguity, so one pass over the text is
  // the whole grammar. A key is a string followed by a colon, and that
  // alternative comes first so it wins over the plain-string one.
  var TOK = /("(?:\\.|[^"\\])*")(\s*:)|("(?:\\.|[^"\\])*")|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

  // Escaped BEFORE tokenizing, and quotes are deliberately left alone: inside
  // element text a bare " is not markup, and turning it into &quot; would stop
  // the string pattern matching. After this the only tags in the result are the
  // spans added below, which is what makes assigning to innerHTML safe here.
  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function paint() {
    hl.innerHTML = esc(ta.value).replace(TOK, function (m, key, colon, str, lit, num) {
      if (key) { return '<span class="k">' + key + "</span>" + colon; }
      if (str) { return '<span class="s">' + str + "</span>"; }
      if (lit) { return '<span class="l">' + lit + "</span>"; }
      return '<span class="n">' + num + "</span>";
    }) + "\n";           // trailing newline so the last line can scroll into view
    hl.scrollTop = ta.scrollTop;
    hl.scrollLeft = ta.scrollLeft;
  }

  // Where the error is matters more than what colour anything is: the server
  // refuses a malformed overlay anyway, so the only job here is to say which
  // character before Save is pressed.
  // The two engines word this differently and neither is going to change:
  // V8 says "at position 42", SpiderMonkey says "at line 3 column 27". Parsing
  // only one of them means the caret silently fails to move in half the
  // browsers, which is worse than not offering it.
  function offsetOf(msg, text) {
    var m = /position (\d+)/.exec(msg);
    if (m) { return +m[1]; }
    m = /line (\d+) column (\d+)/.exec(msg);
    if (m) {
      var lines = text.split("\n"), off = 0, i;
      for (i = 0; i < +m[1] - 1 && i < lines.length; i++) { off += lines[i].length + 1; }
      return off + (+m[2] - 1);
    }
    return -1;
  }
  function check(moveCaret) {
    try {
      JSON.parse(ta.value);
      validEl.textContent = "";
      validEl.className = "";
      return true;
    } catch (e) {
      var off = offsetOf(e.message, ta.value);
      var where = "";
      if (off >= 0) {
        if (!/line \d+ column \d+/.test(e.message)) {   // do not repeat what it already said
          var upto = ta.value.slice(0, off);
          where = " - line " + upto.split("\n").length +
                  ", column " + (upto.length - upto.lastIndexOf("\n"));
        }
        if (moveCaret) { ta.focus(); ta.setSelectionRange(off, off); }
      }
      validEl.textContent = "invalid JSON: " + e.message + where;
      validEl.className = "err";
      return false;
    }
  }
  function refresh() { paint(); check(false); }
  ta.addEventListener("input", refresh);
  ta.addEventListener("scroll", function () {
    hl.scrollTop = ta.scrollTop;
    hl.scrollLeft = ta.scrollLeft;
  });
  function load() {
    show("loading...");
    fetch(API, { method: "GET", headers: { "Accept": "application/json" } })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (d) {
        etag = d.etag;
        ta.value = JSON.stringify(d.policy, null, 2);
        refresh();
        show("loaded (etag " + etag + "). Registered tools: " + d.tools.join(", "), "ok");
      })
      .catch(function (e) { show("load failed: " + e.message, "err"); });
  }
  function save() {
    if (!check(true)) { show("not valid JSON - the caret is on it", "err"); return; }
    var parsed = JSON.parse(ta.value);
    show("saving...");
    fetch(API, {
      method: "PUT",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "If-Match": etag || "" },
      body: JSON.stringify(parsed)
    }).then(function (r) {
      return r.json().then(function (d) { return { status: r.status, body: d }; });
    }).then(function (res) {
      if (res.status === 200) {
        etag = res.body.etag;
        ta.value = JSON.stringify(res.body.policy, null, 2);
        refresh();
        show("saved. new etag " + etag, "ok");
      } else if (res.status === 412) {
        etag = res.body.etag;
        show("conflict: policy changed under you (etag now " + etag + "). Reload, reapply, save again.", "err");
      } else {
        show("rejected (HTTP " + res.status + "): " + (res.body.error || "unknown"), "err");
      }
    }).catch(function (e) { show("save failed: " + e.message, "err"); });
  }
  document.getElementById("save").addEventListener("click", save);
  document.getElementById("reload").addEventListener("click", load);
  load();
})();
</script>
</body>
</html>
"""
