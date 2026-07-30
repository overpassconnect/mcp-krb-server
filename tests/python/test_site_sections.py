"""CLIENT_SITE_SECTIONS: the injector run.sh uses to add a deployment's own
sections to the provisioning page.

The injector is a python heredoc inside run.sh rather than a separate file, so
these tests extract and execute that exact block. Testing a copy would let the
shipped code and the tested code drift, which is the whole failure this feature
exists to prevent: a deployment hand-editing its served page, then losing the
edit at the next install with nothing able to regenerate it.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_SH = ROOT / "server" / "install" / "run.sh"
PAGE = ROOT / "client" / "web" / "index.html"


def injector_source():
    """The python between <<'PY' and PY inside inject_site_sections()."""
    text = RUN_SH.read_text(encoding="utf-8")
    start = text.index("inject_site_sections()")
    body = text[start:]
    # The heredoc line carries a trailing `|| die ...`, so do not anchor on a
    # newline immediately after the delimiter.
    m = re.search(r"<<'PY'[^\n]*\n(.*?)\nPY\n", body, re.S)
    assert m, "could not find the injector heredoc in run.sh"
    return m.group(1)


def run_injector(page_text, fragment):
    """Execute the shipped injector over a temp page and fragment."""
    with tempfile.TemporaryDirectory() as d:
        page = Path(d) / "index.html"
        page.write_text(page_text, encoding="utf-8")
        frag = Path(d) / "sections.html"
        frag.write_text(fragment, encoding="utf-8")

        src = Path(d) / "inject.py"
        src.write_text(injector_source(), encoding="utf-8")

        env = dict(os.environ, SECTIONS_FILE=str(frag))
        proc = subprocess.run([sys.executable, str(src), str(page)],
                              capture_output=True, text=True, env=env)
        return proc, page.read_text(encoding="utf-8")


MINIMAL = """<html><body>
  <nav class="os">
    <a href="#linux">Linux</a>
    <!-- site-nav -->
    <a href="#artifacts">Artifacts</a>
  </nav>
  <!-- site-sections -->

  <section id="artifacts"><h2>Artifacts</h2></section>
</body></html>
"""

ONE = '<section id="containers"><h2>Proxmox container</h2><p>x</p></section>\n'


class TestInjection(unittest.TestCase):

    def test_section_and_nav_are_both_added(self):
        proc, out = run_injector(MINIMAL, ONE)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('<section id="containers">', out)
        self.assertIn('<a href="#containers">Proxmox container</a>', out)

    def test_nav_entry_lands_before_artifacts(self):
        # Order matters: a deployment's sections belong with the platforms, not
        # after the artifact table.
        _, out = run_injector(MINIMAL, ONE)
        self.assertLess(out.index('href="#containers"'), out.index('href="#artifacts"'))

    def test_markers_are_consumed(self):
        _, out = run_injector(MINIMAL, ONE)
        self.assertNotIn("<!-- site-nav -->", out)
        self.assertNotIn("<!-- site-sections -->", out)

    def test_h2_markup_is_stripped_for_the_nav_label(self):
        frag = ('<section id="ct"><h2><img src="i.svg" alt="">Containers'
                '<span class="tag">IT only</span></h2></section>')
        _, out = run_injector(MINIMAL, frag)
        self.assertIn('<a href="#ct">Containers IT only</a>', out)
        self.assertNotIn('<a href="#ct"><img', out)

    def test_a_trailing_tag_span_does_not_run_into_the_title(self):
        # Shipped as "Proxmox containerIT only" in the live nav: stripping tags
        # to nothing joins the title to its badge. Tags become a space instead.
        frag = ('<section id="ct"><h2>Proxmox container'
                '<span class="tag">IT only</span></h2></section>')
        _, out = run_injector(MINIMAL, frag)
        self.assertNotIn("containerIT", out)
        self.assertIn('<a href="#ct">Proxmox container IT only</a>', out)

    def test_several_sections_each_get_an_entry(self):
        frag = ('<section id="a"><h2>Alpha</h2></section>\n'
                '<section id="b"><h2>Beta</h2></section>\n')
        _, out = run_injector(MINIMAL, frag)
        self.assertIn('href="#a"', out)
        self.assertIn('href="#b"', out)

    def test_fragment_with_no_section_is_an_error(self):
        # Silently injecting unreachable markup would be worse than refusing:
        # the content would be served but unlinked, so nobody would find it.
        proc, out = run_injector(MINIMAL, "<p>just a paragraph</p>")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("no <section", proc.stderr)

    def test_page_without_markers_is_an_error(self):
        proc, _ = run_injector("<html><body></body></html>", ONE)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("marker", proc.stderr)

    def test_prose_quoting_a_marker_is_not_mistaken_for_one(self):
        # This shipped broken. The page's header comment documents the markers
        # by quoting them, and that comment is above the real ones, so a
        # first-occurrence replace put the whole injected section inside the
        # comment: invisible on the page, no nav entry, and no error anywhere.
        page = MINIMAL.replace(
            "<html><body>",
            "<html>\n<!--\n  run.sh injects at the <!-- site-sections --> and\n"
            "  <!-- site-nav --> markers below.\n-->\n<body>")
        proc, out = run_injector(page, ONE)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # the section must land in the body, after the documentation comment
        self.assertLess(out.index("markers below"), out.index('<section id="containers">'))
        # and the nav entry must be in the real nav, not the prose
        nav = out[out.index('<nav class="os">'):out.index("</nav>")]
        self.assertIn('href="#containers"', nav)

    def test_indented_marker_still_matches(self):
        # The real page indents them; only whitespace may surround one.
        page = MINIMAL.replace("  <!-- site-sections -->", "        <!-- site-sections -->")
        proc, out = run_injector(page, ONE)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('<section id="containers">', out)

    def test_marker_with_trailing_text_on_the_line_does_not_match(self):
        page = MINIMAL.replace("  <!-- site-sections -->",
                               "  <!-- site-sections --> <p>trailing</p>")
        proc, _ = run_injector(page, ONE)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("line of its own", proc.stderr)

    def test_shipped_page_carries_both_markers(self):
        # If someone removes a marker while editing the page, every deployment's
        # sections vanish at the next install. Catch that here, not in the field.
        page = PAGE.read_text(encoding="utf-8")
        self.assertIn("<!-- site-nav -->", page)
        self.assertIn("<!-- site-sections -->", page)

    def test_injection_into_the_real_shipped_page(self):
        proc, out = run_injector(PAGE.read_text(encoding="utf-8"), ONE)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('<a href="#containers">Proxmox container</a>', out)
        # and the platform sections survive intact
        for sid in ("linux", "windows", "macos", "artifacts"):
            self.assertIn('id="%s"' % sid, out)

    def test_output_has_no_carriage_returns(self):
        # The injector writes with newline='' so a Windows python cannot turn a
        # served shell script's page into CRLF soup.
        _, out = run_injector(MINIMAL, ONE)
        self.assertNotIn("\r", out)


if __name__ == "__main__":
    unittest.main()
