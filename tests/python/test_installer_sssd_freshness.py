"""The installer keeps SSSD's group answers at most a second old.

authz.ipa_groups() resolves a caller's groups through SSSD on every tool call,
and SSSD's defaults reuse an answer for 90 minutes and keep it on disk. On a live
host that meant a user added to a group in IPA kept being refused through a
reboot. run.sh step 2b writes an SSSD snippet that caps the cache at one second
and switches off SSSD's in-memory cache; verify.sh check 11 confirms SSSD applied
it.

Like test_installer_editor_guard.py this reads the scripts rather than running
them, because run.sh needs root, a real SSSD and an enrolled host. That is weaker
than a behavioural test. What it defends against is the realistic regression: the
setting, its file mode, or the verifier's path drifting away during an edit, so
that a rebuilt host quietly goes back to 90 minutes. The one behavioural part is
parsing the rendered snippet as the INI file SSSD reads.
"""
import configparser
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "server" / "install"
RUN = (INSTALL / "run.sh").read_text(encoding="utf-8")
VERIFY = (INSTALL / "verify.sh").read_text(encoding="utf-8")

SNIPPET_PATH = "/etc/sssd/conf.d/50-mcp-authz-nocache.conf"


def rendered_snippet(domain):
    m = re.search(r'cat > "\$TMPROOT/sssd-snippet\.conf" <<EOF\n(.*?)\nEOF\n', RUN, re.S)
    if m is None:
        raise AssertionError("run.sh no longer renders the SSSD snippet from a heredoc")
    return m.group(1).replace("$IPA_DOMAIN", domain)


class TheSnippet(unittest.TestCase):

    def test_parses_as_ini_with_the_settings_that_matter(self):
        cfg = configparser.ConfigParser(strict=True, interpolation=None)
        cfg.read_string(rendered_snippet("example.internal"))
        self.assertEqual(cfg["domain/example.internal"]["entry_cache_timeout"], "1")
        self.assertEqual(cfg["domain/example.internal"]["entry_cache_nowait_percentage"], "0")
        self.assertEqual(cfg["nss"]["memcache_timeout"], "0")

    def test_no_shell_expansion_survives_but_the_domain(self):
        # The heredoc is unquoted so $IPA_DOMAIN expands. Anything else that looks
        # like an expansion would be expanded too, silently.
        body = rendered_snippet("example.internal")
        self.assertNotIn("$", body)
        self.assertNotIn("`", body)


class TheInstaller(unittest.TestCase):

    def test_installs_it_root_owned_0600(self):
        # SSSD skips a snippet with any other owner or mode, without failing.
        self.assertIn(SNIPPET_PATH, RUN)
        self.assertRegex(
            RUN, r'run install -m 0600 -o root -g root "\$TMPROOT/sssd-snippet\.conf" "\$SSSD_SNIPPET"')

    def test_restarts_sssd_and_expires_what_was_cached_before(self):
        # The timeout only applies to records fetched after it.
        self.assertIn("run systemctl restart sssd", RUN)
        self.assertIn("run sss_cache -E", RUN)

    def test_sss_cache_is_installed(self):
        for line in re.findall(r'PKGS="([^"]*)"', RUN):
            self.assertIn("sssd-tools", line.split(), "a package list lacks sssd-tools: " + line)


class TheVerifier(unittest.TestCase):

    def test_checks_the_same_file_the_installer_writes(self):
        self.assertIn("SSSD_SNIPPET=" + SNIPPET_PATH, VERIFY)
        self.assertIn("SSSD_SNIPPET=" + SNIPPET_PATH, RUN)

    def test_asks_sssd_whether_it_applied_it(self):
        # A correct file that SSSD skipped looks identical from the file's side.
        self.assertIn("/var/lib/sss/mc/", VERIFY)
        self.assertIn('"root:root 600"', VERIFY)


if __name__ == "__main__":
    unittest.main()
