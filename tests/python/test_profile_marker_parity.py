"""setup.ps1 and uninstall.ps1 have to agree about the PowerShell profile.

The profile is the one thing the kit edits rather than creates, so both halves
work by pattern: setup.ps1 strips its own functions by name before rewriting
them (that is what makes a re-run idempotent), and uninstall.ps1 strips them by
the marker comment stamped on each line (by marker and never by name, so a
user's own `function wslssh` survives).

Two lists therefore have to track the functions being written, and neither is
anywhere near the line that writes them. That drifted: wslgit was added to
setup.ps1 with a marker uninstall.ps1 never carried, so from that day every
uninstall silently left wslgit behind in the profile. Nothing failed, nothing
was logged, and the file's own comment already warned this would happen.

These are the checks that would have said so.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SETUP = (ROOT / "client" / "setup.ps1").read_text(encoding="utf-8")
UNINSTALL = (ROOT / "client" / "uninstall.ps1").read_text(encoding="utf-8")

# $kept += "function NAME { ... }   # Kerberos ... (setup.ps1)"
# Anchored on the whole line: the wslgit body contains backtick-escaped quotes,
# so a naive "([^"]*)" would end the match in the middle of it.
WRITES = re.findall(
    r'^\$kept \+= "function ([\w-]+)\b.*?(# Kerberos .*? \(setup\.ps1\))"\s*$',
    SETUP, re.M)


def stripped_names():
    """The alternation setup.ps1 removes before re-adding its functions."""
    m = re.search(r"function\\s\+\(([^)]+)\)\\b", SETUP)
    assert m, "the profile idempotency regex is not where this test expects it"
    return m.group(1).split("|")


def uninstall_markers():
    m = re.search(r"\$markers = @\((.*?)\n\)", UNINSTALL, re.S)
    assert m, "$markers array not found in uninstall.ps1"
    return re.findall(r"'(#[^']*)'", m.group(1))


class ThePageTeachesTheHelpers(unittest.TestCase):
    """The page kept teaching the long form after the short one existed.

    `wsl kinit user@REALM` still works, so nothing failed and nothing flagged it.
    The helper was simply undiscoverable to anyone who provisioned from the page
    rather than reading setup.ps1, which is everyone."""

    PAGE = (ROOT / "client" / "web" / "index.html").read_text(encoding="utf-8")

    def test_the_page_does_not_teach_the_long_form(self):
        for stale in ("wsl kinit", "wsl klist", "wsl kdestroy"):
            self.assertNotIn(
                stale, self.PAGE,
                "the page still teaches %r, which setup.ps1 replaced with a "
                "profile function" % stale)

    def test_every_function_the_installer_writes_is_shown(self):
        for name, _marker in WRITES:
            self.assertIn(name, self.PAGE,
                          "setup.ps1 adds %s to the user's profile and the page "
                          "never mentions it, so nobody knows it exists" % name)


class TestProfileFunctionsAreTracked(unittest.TestCase):

    def test_setup_writes_functions_this_test_can_see(self):
        # Without this the whole file passes vacuously the moment the regex
        # stops matching, which is exactly when it is most needed.
        names = [n for n, _ in WRITES]
        self.assertIn("wslssh", names)
        self.assertIn("wslgit", names)
        self.assertGreaterEqual(len(WRITES), 6)

    def test_every_written_function_is_stripped_before_rewriting(self):
        stripped = stripped_names()
        missing = [n for n, _ in WRITES if n not in stripped]
        self.assertEqual([], missing,
                         "setup.ps1 writes these but does not strip them first, so "
                         "every re-run appends a duplicate definition: %s" % missing)

    def test_every_written_function_can_be_uninstalled(self):
        markers = uninstall_markers()
        orphans = [(n, m) for n, m in WRITES if m not in markers]
        self.assertEqual([], orphans,
                         "setup.ps1 stamps markers uninstall.ps1 does not carry, so "
                         "these functions survive uninstall forever: %s" % orphans)

    def test_uninstall_carries_no_marker_nothing_writes(self):
        # The other direction. A marker left behind after its function is gone
        # is dead code that reads like coverage.
        written = [m for _, m in WRITES]
        stale = [m for m in uninstall_markers() if m not in written]
        self.assertEqual([], stale,
                         "uninstall.ps1 strips markers setup.ps1 never writes: %s" % stale)

    def test_each_function_has_its_own_marker(self):
        markers = [m for _, m in WRITES]
        self.assertEqual(len(markers), len(set(markers)),
                         "two functions share a marker comment, so uninstall cannot "
                         "remove one without the other")

    def test_the_retired_kssh_name_is_still_stripped(self):
        # Profiles provisioned before the rename still define kssh. Dropping it
        # from the alternation leaves those definitions working, updated by
        # nothing, forever. setup.ps1 says so in a comment; this enforces it.
        self.assertIn("kssh", stripped_names())


if __name__ == "__main__":
    unittest.main()
