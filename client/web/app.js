/* app.js - provisioning page script. Progressive enhancement only.
 *
 * Static file, copied verbatim; no hostnames, realms or addresses belong
 * here. Site values come from config.js (window.SITE); the download URL is
 * inferred from where this page is served. Nothing is rendered or substituted
 * at build time, so this file and the page cannot drift apart the way a
 * rendered template can.
 *
 * Four jobs:
 *   1. fill the site markers (__REALM__, __DOMAIN__, __KDC__, __MCP_URL__,
 *      __CA_SHA256__, __DNS_IP__) from config.js, and __BASE__ from the page's
 *      own URL, into every code block. This is the whole "rendering", done in
 *      the browser, once, on load.
 *   2. set the org name (title, logo alt) and the support-email link.
 *   3. point the download links at the inferred base.
 *   4. a copy button per code block, and local fill of the interactive
 *      <OTP> / <hostname> / <your-ipa-username> placeholders.
 *
 * All client side. The page CSP is default-src 'none' with img-src 'self',
 * script-src 'self' and style-src 'unsafe-inline'. config.js loads via
 * <script src>, which script-src 'self' allows, so there is no fetch and no
 * connect-src: nothing here can send a value anywhere. Nothing is written to
 * localStorage or sessionStorage either, so what you type dies with the tab.
 * With JavaScript off the page still reads, you just edit the markers by hand.
 */
(function () {
  'use strict';

  var SITE = window.SITE || {};

  /* The download base is the directory this page was served from, so the
   * commands stay correct wherever the bundle is hosted. '/client/' and
   * '/client/index.html' both yield '<origin>/client'.
   *
   * downloadBase overrides that, for a host that serves the page and the files
   * from different paths: a landing page at / with the artifacts under /d/, say,
   * where the files often carry Content-Disposition: attachment and so cannot
   * share a directory with a page meant to render. Without the override such a
   * host has to hand-edit the page, which forks it from the repo permanently.
   * Relative values are resolved against the origin; absolute URLs pass through
   * so the bundle can be served from one host and the files from another. */
  var BASE = location.origin + location.pathname.replace(/\/[^\/]*$/, '');
  if (SITE.downloadBase) {
    BASE = /^https?:\/\//.test(SITE.downloadBase)
      ? SITE.downloadBase.replace(/\/+$/, '')
      : location.origin + '/' + String(SITE.downloadBase).replace(/^\/+|\/+$/g, '');
  }

  /* Missing config values become a visible <MARKER> rather than a raw __TOKEN__,
   * so a half-filled config.js reads as "set this" instead of looking like a
   * bug in the page. */
  var MAP = {
    '__BASE__': BASE,
    '__DOMAIN__': SITE.domain || '<set domain in config.js>',
    '__REALM__': SITE.realm || '<set realm in config.js>',
    '__KDC__': SITE.kdc || '<set kdc in config.js>',
    '__MCP_URL__': SITE.mcpUrl || '<set mcpUrl in config.js>',
    '__CA_SHA256__': SITE.caSha256 || '<set caSha256 in config.js>',
    /* The whole CA argument, so a site that distributes the certificate by
     * other means (MDM, a golden image) does not hand people a step they
     * would be doing twice. caInstall defaults to true when unset, which
     * keeps every existing config.js behaving as it did. */
    '__CA_ARG__': (SITE.caInstall === false)
      ? '--skip-ca'
      : '--ca-sha256 ' + (SITE.caSha256 || '<set caSha256 in config.js>'),
    '__DNS_IP__': SITE.dnsIp || '<set dnsIp in config.js>',
    /* On-behalf-of forwarding needs the caller's own ticket to be forwardable,
     * and the installers write that line of krb5.conf off by default, which is
     * the right default for a fleet that does not forward. The two facts live on
     * different machines, so they drifted: a server with MCP_DELEGATION=1 served
     * a command guaranteeing delegation could not work, and the contradiction
     * surfaced days later on a developer's laptop as "cannot act on your behalf",
     * which points at neither.
     *
     * So the command carries the switch when, and only when, this deployment
     * actually forwards. run.sh derives `delegation` from MCP_DELEGATION, so
     * nobody has to know the flag exists and the two cannot disagree again.
     * Absent means false, which keeps every existing config.js rendering exactly
     * the command it renders today. */
    '__FWD_PS__': (SITE.delegation === true) ? '-Forwardable' : '',
    '__FWD_SH__': (SITE.delegation === true) ? '--forwardable' : ''
  };

  /* The CA stanza is bracketed by markers rather than commented out, because
   * macOS is zsh and zsh does not treat # as a comment interactively: a
   * commented-out block would paste as "command not found: #". With caInstall
   * false the whole stanza goes; otherwise only the markers do, leaving a block
   * that can be pasted as it stands. */
  function applyCaBlock(text) {
    if (SITE.caInstall === false) {
      return text.replace(/^__CA_BEGIN__\n[\s\S]*?^__CA_END__\n/m, '');
    }
    return text.replace(/^__CA_(?:BEGIN|END)__\n/gm, '');
  }

  function applySite(text) {
    text = applyCaBlock(text);
    for (var k in MAP) {
      if (MAP.hasOwnProperty(k)) { text = text.split(k).join(MAP[k]); }
    }
    return text;
  }

  /* 1. bake site values into every code block before the interactive fill
   *    captures its templates below. */
  var codes = document.querySelectorAll('code');
  for (var i = 0; i < codes.length; i++) {
    codes[i].textContent = applySite(codes[i].textContent);
  }

  /* A code block whose whole content was a CA stanza is now empty, because
   * caInstall is false on this deployment. Leave it in place and the page shows
   * an empty grey box with a copy button that copies nothing. Hide the <pre>,
   * and the note that introduces it, so the step disappears rather than
   * appearing broken. Only ever hides blocks that are ACTUALLY empty, so a
   * deployment that installs the CA is untouched. */
  var pres = document.querySelectorAll('pre');
  for (var p = 0; p < pres.length; p++) {
    var c = pres[p].querySelector('code');
    if (c && c.textContent.trim() === '') {
      pres[p].style.display = 'none';
      var prev = pres[p].previousElementSibling;
      if (prev && prev.classList.contains('note')) { prev.style.display = 'none'; }
    }
  }

  /* 2a. org name onto the title and the logo alt text. */
  if (SITE.orgName) {
    document.title = 'Machine provisioning | ' + SITE.orgName;
    var logos = document.querySelectorAll('[data-alt-org]');
    for (var l = 0; l < logos.length; l++) { logos[l].setAttribute('alt', SITE.orgName); }
  }

  /* 2b. support email. No connect-src, so a mailto is the only contact channel
   *     the CSP permits. */
  var mail = document.querySelector('.help-mail');
  if (mail) {
    if (SITE.supportEmail) {
      mail.setAttribute('href', 'mailto:' + SITE.supportEmail);
      mail.textContent = SITE.supportEmail;
    }
  }

  /* 3. download links point at the inferred base. */
  var files = document.querySelectorAll('a[data-file]');
  for (var f = 0; f < files.length; f++) {
    files[f].setAttribute('href', BASE + '/' + files[f].getAttribute('data-file'));
  }

  /* 4a. copy button per code block. */
  var COPY_SVG = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
  var DONE_SVG = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>';

  function addCopy(pre) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'copy';
    btn.title = 'Copy to clipboard';
    btn.setAttribute('aria-label', 'Copy to clipboard');
    btn.innerHTML = COPY_SVG;
    btn.addEventListener('click', function () {
      var code = pre.querySelector('code');
      var text = (code ? code.textContent : pre.textContent);
      var ok = function () {
        btn.innerHTML = DONE_SVG;
        btn.classList.add('ok');
        setTimeout(function () { btn.innerHTML = COPY_SVG; btn.classList.remove('ok'); }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(ok, fallback);
      } else {
        fallback();
      }
      function fallback() {
        var r = document.createRange();
        r.selectNodeContents(code || pre);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(r);
      }
    });
    pre.appendChild(btn);
  }

  var pres = document.querySelectorAll('pre');
  for (var p = 0; p < pres.length; p++) { addCopy(pres[p]); }

  /* 4b. local placeholder fill. Any <div class="fill" data-fill="ID"> drives the
   *     <code id="ID"> below it. Each <input data-token="..."> replaces that
   *     literal token in the command. The template captured here is already
   *     site-filled by step 1, so the two layers compose. */
  var groups = document.querySelectorAll('[data-fill]');
  for (var g = 0; g < groups.length; g++) {
    (function (group) {
      var target = document.getElementById(group.getAttribute('data-fill'));
      if (!target) { return; }
      var template = target.textContent;      // captured after site-fill
      var fields = group.querySelectorAll('input[data-token]');
      function fill() {
        var out = template;
        for (var k = 0; k < fields.length; k++) {
          var token = fields[k].getAttribute('data-token');
          var val = fields[k].value.trim();
          if (val) { out = out.split(token).join(val); }
        }
        target.textContent = out;
      }
      for (var k = 0; k < fields.length; k++) {
        fields[k].addEventListener('input', fill);
      }
    })(groups[g]);
  }

  /* 5. sidebar tabs: one platform section at a time. body.tabs is set here and
   *    only here, so with scripts off none of the tab CSS engages and the page
   *    stays the single scrolling document. Deep links keep working: a #hash
   *    on load selects that tab, and switching uses replaceState so the back
   *    button does not fill up with tab flips. */
  var tabLinks = document.querySelectorAll('nav.os a[href^="#"]');
  var panes = [];
  var wired = tabLinks.length > 0;
  for (var n = 0; n < tabLinks.length; n++) {
    var pane = document.getElementById(tabLinks[n].getAttribute('href').slice(1));
    if (!pane) { wired = false; break; }
    panes.push(pane);
  }
  if (wired) {
    document.body.classList.add('tabs');

    function selectTab(id) {
      var found = false;
      for (var i = 0; i < panes.length; i++) {
        if (panes[i].id === id) {
          panes[i].classList.add('current');
          tabLinks[i].classList.add('on');
          found = true;
        } else {
          panes[i].classList.remove('current');
          tabLinks[i].classList.remove('on');
        }
      }
      return found;
    }

    for (var w = 0; w < tabLinks.length; w++) {
      (function (link, pane) {
        link.addEventListener('click', function (ev) {
          ev.preventDefault();
          selectTab(pane.id);
          if (window.history && history.replaceState) {
            history.replaceState(null, '', '#' + pane.id);
          } else {
            location.hash = pane.id;
          }
          /* Under 860px the layout is the stacked original with every section
           * visible, so a tab tap should still travel to the section the way
           * the plain anchor would have. */
          if (window.matchMedia && matchMedia('(max-width: 860px)').matches) {
            pane.scrollIntoView();
          }
        });
      })(tabLinks[w], panes[w]);
    }

    /* Which tab opens first. A #hash wins, because a deep link someone was
     * sent is a stronger signal than a guess. Otherwise open the tab for the
     * visitor's own OS: almost everyone arriving here is provisioning the
     * machine they are reading this on, and landing them on Linux when they
     * are on a Mac just makes them hunt.
     *
     * userAgentData is the modern source and undefined in Safari and Firefox,
     * so userAgent is the fallback rather than the other way round. Order
     * matters: iOS and Android both report platforms that match the desktop
     * patterns, and neither has a section here, so they fall through to the
     * default rather than being shown a page they cannot follow. */
    function detectedTab() {
      var uaData = navigator.userAgentData;
      var s = (uaData && uaData.platform) || navigator.platform ||
              navigator.userAgent || '';
      if (/Android|iPhone|iPad|iPod/i.test(navigator.userAgent || '')) { return null; }
      if (/Mac|Darwin/i.test(s)) { return 'macos'; }
      if (/Win/i.test(s)) { return 'windows'; }
      if (/Linux|X11|CrOS/i.test(s)) { return 'linux'; }
      return null;
    }

    if (!location.hash || !selectTab(location.hash.slice(1))) {
      var guess = detectedTab();
      if (!guess || !selectTab(guess)) { selectTab(panes[0].id); }
    }
  }
})();
