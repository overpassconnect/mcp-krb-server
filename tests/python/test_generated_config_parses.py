"""The config.js run.sh writes must be valid JavaScript.

This is the second time the same mistake shipped. config.example.js was invalid
for months because a key was appended after the last one without giving the
previous line a comma, and the whole object literal became a SyntaxError:
window.SITE never gets defined, and the page renders with every token
unresolved. That one was caught by rendering the page.

The fix added tests for config.example.js and stopped there, which missed the
point: run.sh's write_config is a *second*, independent generator of the same
file, and it is the one every real deployment actually uses. The example is only
read by someone hand-writing a config. So the identical bug was reintroduced
within a day, in the generator, and again reported success while emitting a file
no browser can parse.

These tests extract write_config's format strings and check the comma discipline
that both failures broke, and, where node is available, evaluate the generated
document to prove it leaves a populated window.SITE.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN = (ROOT / "server" / "install" / "run.sh").read_text(encoding="utf-8")
NODE = shutil.which("node")


def write_config_body():
    start = RUN.index("write_config()")
    return RUN[start:RUN.index('} > "$1/config.js"', start)]


def emitted_key_lines():
    """The printf lines that emit `  key: value` into the object literal."""
    return re.findall(r'printf\s+"(\s*[A-Za-z_][A-Za-z0-9_]*:[^"]*)"', write_config_body())


SH = shutil.which("sh")


def render(delegation="1", ca_install="yes"):
    """Run the real write_config and return the config.js it produces.

    The function is lifted out of run.sh and executed, rather than having its
    output reconstructed here. A reconstruction is what this test file exists to
    avoid: it would keep agreeing with itself while the shipped generator
    emitted something no browser can parse, which is exactly what happened."""
    src = RUN[RUN.index("js_str()"):]
    end = src.index('chmod 0644 "$1/config.js"')
    body = src[:src.index("\n", end) + 1] + "}\n"

    with tempfile.TemporaryDirectory() as d:
        script = "\n".join([
            "set -eu",
            "CLIENT_ORG='Example Ltd'", "CLIENT_DOMAIN=example.internal",
            "REALM=EXAMPLE.INTERNAL", "CLIENT_KDC=ipa.example.internal",
            "CLIENT_MCP_URL=https://mcp.example.internal/",
            "CLIENT_CA_SHA256=abc123", "CLIENT_DNS=10.0.0.53",
            "CLIENT_SUPPORT_EMAIL=''", "CLIENT_DOWNLOAD_BASE=/d",
            "CLIENT_CA_INSTALL=%s" % ca_install,
            "MCP_DELEGATION=%s" % delegation,
            body,
            'write_config "%s"' % d.replace("\\", "/"),
        ])
        r = subprocess.run([SH, "-c", script], capture_output=True, text=True)
        if r.returncode != 0:
            raise AssertionError("write_config failed: %s" % (r.stderr or r.stdout))
        return (Path(d) / "config.js").read_text(encoding="utf-8")


class CommaDiscipline(unittest.TestCase):

    def test_the_generator_emits_keys_this_test_can_see(self):
        keys = emitted_key_lines()
        self.assertIn('  orgName:', ''.join(keys))
        self.assertGreaterEqual(len(keys), 8)

    def test_every_key_but_the_last_ends_with_a_comma(self):
        keys = emitted_key_lines()
        missing = [k.strip() for k in keys[:-1] if not k.rstrip('\\n').rstrip().endswith(',')]
        self.assertEqual([], missing,
                         "these keys are followed by another and have no trailing comma, "
                         "so the object literal is a SyntaxError and window.SITE never "
                         "gets defined: %s" % missing)

    def test_the_last_key_has_no_trailing_comma(self):
        # Harmless in modern engines, but the file is read by whatever browser
        # the user has, and the existing style is to omit it.
        last = emitted_key_lines()[-1].rstrip('\\n').rstrip()
        self.assertFalse(last.endswith(','),
                         "the final key has a trailing comma: %r" % last)


class TheRenderedDocumentIsValid(unittest.TestCase):
    """Structure only, deliberately.

    js_str's escaping expression is rejected by some sed builds (Git Bash's,
    notably), so on those platforms every string value renders empty while the
    document's shape is unaffected. The shape is what both shipped failures
    broke, so the tests below assert that and the anti-vacuity check keeps an
    empty render from passing them by accident."""

    @unittest.skipUnless(SH, "sh not available")
    def test_the_render_is_a_real_document(self):
        out = render()
        for expected in ("window.SITE = {", "orgName:", "caInstall:", "delegation:", "};"):
            self.assertIn(expected, out,
                          "the harness produced something that is not the generated "
                          "config, so the checks below would pass on nothing")

    @unittest.skipUnless(NODE and SH, "node or sh not available")
    def test_it_parses_as_javascript(self):
        r = subprocess.run([NODE, "--check", "-"], input=render(),
                           capture_output=True, text=True)
        self.assertEqual(0, r.returncode,
                         "run.sh writes a config.js that no browser can parse:\n%s\n"
                         "--- rendered ---\n%s" % (r.stderr, render()))

    @unittest.skipUnless(NODE and SH, "node or sh not available")
    def test_it_leaves_a_populated_window_site(self):
        script = "var window={};" + render() + ";if(typeof window.SITE!=='object')process.exit(1);"
        r = subprocess.run([NODE, "-e", script], capture_output=True, text=True)
        self.assertEqual(0, r.returncode,
                         "the generated config parses but defines no window.SITE:\n%s"
                         % (r.stderr or r.stdout))


if __name__ == "__main__":
    unittest.main()
