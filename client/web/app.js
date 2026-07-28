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
   * '/client/index.html' both yield '<origin>/client'. */
  var BASE = location.origin + location.pathname.replace(/\/[^\/]*$/, '');

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
    '__DNS_IP__': SITE.dnsIp || '<set dnsIp in config.js>'
  };

  function applySite(text) {
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
})();
