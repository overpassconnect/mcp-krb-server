/* config.example.js - site values for the provisioning page.
 *
 * Copy to config.js and edit, OR let server/install/run.sh write config.js for
 * you (it derives most of these from the install and needs no hand-editing).
 * config.js sits next to index.html and is loaded before app.js.
 *
 * There is NO download URL here, deliberately. The page infers it from where it
 * is served, so the same bundle works from any host you copy it to. Nothing in
 * this file is secret: the realm, domain and KDC are already on every enrolled
 * machine, and the CA hash is public. Do not put a keytab, password or private
 * key here.
 */
window.SITE = {
  orgName: 'Example Ltd',                 // shown in the title and logo alt
  domain: 'example.internal',             // DNS domain
  realm: 'EXAMPLE.INTERNAL',              // Kerberos realm
  kdc: 'ipa.example.internal',            // FreeIPA server / KDC, bare FQDN
  mcpUrl: 'https://mcp.example.internal/', // the Kerberized MCP API the bridge talks to
  caSha256: '',                           // sha256sum of /etc/ipa/ca.crt, optional (Windows/macOS CA pin)
  dnsIp: '',                              // resolver that answers for `domain`, optional (macOS split DNS)
  supportEmail: ''                        // optional; blank leaves a generic "contact your IT team"
};
