"""Ticket forwardability has to be reachable by the person installing.

The requirement itself is documented well: README.md states it, client/README.md
gives it a section, SECURITY.md lists it as a [D1] prerequisite. None of that is
what a developer reads while provisioning a laptop. They read the page the MCP
host serves, and that page said nothing at all.

The failure this guards against is the one it caused. A developer installed from
the page, got the default `forwardable = false`, and every on-behalf-of tool
refused with `cannot act on your behalf` days later. The refusal comes from the
KDC, so it reads as a delegation policy problem and sends you to inspect FreeIPA,
where everything is correct. Nothing anywhere connects it back to a switch on an
install command.

macOS was worse than undocumented: it hardcoded `forwardable = false` with no
argument, so a Mac could not opt in at all even knowing the answer.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = (ROOT / "client" / "web" / "index.html").read_text(encoding="utf-8")
MACOS = (ROOT / "client" / "setup-macos.sh").read_text(encoding="utf-8")
PS1 = (ROOT / "client" / "setup.ps1").read_text(encoding="utf-8")


def section(page, sid):
    m = re.search(r'<section id="%s".*?</section>' % sid, page, re.S)
    assert m, "no section id=%r on the page" % sid
    return m.group(0)


class BothKitsCanOptIn(unittest.TestCase):

    def test_windows_has_the_switch(self):
        self.assertRegex(PS1, r"\[switch\]\$Forwardable")

    def test_macos_has_the_switch(self):
        # It hardcoded false with no flag, so a Mac could not use [D1] at all.
        self.assertRegex(MACOS, r"--forwardable\)\s*FORWARDABLE=1")

    def test_macos_renders_the_value_rather_than_a_literal(self):
        self.assertIn("forwardable = $FWD", MACOS,
                      "setup-macos.sh writes a literal again, so the flag does nothing")

    def test_macos_precomputes_the_value_outside_the_heredoc(self):
        # setup.ps1 records getting this wrong twice: an expression evaluated
        # inside the here-string tested a variable that was not a parameter, so
        # it emitted 'false' unconditionally while looking configurable.
        body = MACOS[:MACOS.index("forwardable = $FWD")]
        self.assertIn('if [ "$FORWARDABLE" = 1 ]; then FWD=true; else FWD=false; fi', body)

    def test_off_is_still_the_default_on_both(self):
        self.assertIn("FORWARDABLE=0", MACOS)
        self.assertRegex(PS1, r"\$fwd = if \(\$Forwardable\) \{ 'true' \} else \{ 'false' \}")


class ThePageSaysSo(unittest.TestCase):
    """The page is the only one of these a person installing actually reads."""

    def test_the_windows_tab_names_the_switch(self):
        self.assertIn("-Forwardable", section(PAGE, "windows"))

    def test_the_macos_tab_names_the_switch(self):
        self.assertIn("--forwardable", section(PAGE, "macos"))

    def test_both_tabs_name_the_symptom(self):
        # The whole point: someone hitting the error can search for its text and
        # land on the thing that causes it.
        for sid in ("windows", "macos"):
            self.assertIn("cannot act on your behalf", section(PAGE, sid),
                          "the %s tab does not connect the switch to the error it "
                          "produces, so the error stays unsearchable" % sid)

    def test_both_tabs_say_it_cannot_be_fixed_by_re_running_alone(self):
        # The flag is fixed into the ticket at issue time, so a re-run without
        # destroying the existing ticket looks like it changed nothing.
        for sid in ("windows", "macos"):
            self.assertIn("kdestroy", section(PAGE, sid))


if __name__ == "__main__":
    unittest.main()
