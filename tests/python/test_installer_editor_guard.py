"""The installer must not turn the policy editor off by omission.

run.sh cannot be driven from a unit test: it needs root, a real systemd, a real
keytab and a live KDC. So this reads the script rather than running it. That is
weaker than a behavioural test and worth stating plainly; what it defends
against is the realistic regression, which is the guard being dropped or
loosened during an edit, not the guard being subtly wrong.

Why it exists. --enable-authz-editor is a flag and deliberately not a site.env
key, because the editor is an authenticated write surface over tool
authorization and enabling it should be a person's decision, not a parameter
file's. The cost of that design is that a plain re-run, which is how every other
setting converges, silently switched it OFF. That happened on a live host: a
routine re-run to deploy an unrelated fix took the editor down, and the only
symptom was a 404 on a page nobody had open.

The consequence was not cosmetic. With the editor off the server stops reading
the policy overlay, so the reviewed in-code defaults become the live policy and
every tool the overlay was managing silently changes hands. The file itself was
never touched, which is what made it hard to see: the policy was intact and
unread.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN = (ROOT / "server" / "install" / "run.sh").read_text(encoding="utf-8")


class TheGuardExists(unittest.TestCase):

    def test_both_flags_are_accepted(self):
        for flag in ("--enable-authz-editor", "--disable-authz-editor"):
            self.assertRegex(
                RUN, r"\n\s*%s\)" % re.escape(flag),
                "%s is not in the argument parser, so it cannot be asked for" % flag)

    def test_a_plain_rerun_refuses_when_the_editor_is_on(self):
        # The condition that matters: no enable, no explicit disable, and the
        # INSTALLED unit says the editor is on.
        self.assertRegex(
            RUN,
            r'\[ "\$ENABLE_AUTHZ_EDITOR" != 1 \]\s*&&\s*\[ "\$DISABLE_AUTHZ_EDITOR" != 1 \]'
            r'[\s\\]*&&\s*\[ -f "\$UNIT" \]'
            r'[\s\\]*&&\s*grep -q .\^Environment=MCP_AUTHZ_EDITOR=1',
            "the guard against silently disabling the editor is gone or its "
            "condition changed shape")

    def test_the_guard_reads_the_installed_unit_not_site_env(self):
        # Inferring "it was on" from site.env would re-open the hole the
        # MCP_AUTHZ_EDITOR check closes: a parameter file would once again decide
        # whether an authenticated write surface is served. The installed unit is
        # the state the host is actually in.
        guard = RUN[RUN.index('would turn it off') - 1200:RUN.index('would turn it off')]
        self.assertIn('"$UNIT"', guard)
        self.assertNotIn('SITE_ENV', guard)

    def test_the_guard_names_both_ways_out(self):
        # A refusal that does not say what to type is a worse outage than the
        # one it prevents.
        stop = RUN[RUN.index('the policy editor is ON on this host'):][:1200]
        self.assertIn('--enable-authz-editor', stop)
        self.assertIn('--disable-authz-editor', stop)

    def test_the_stop_explains_the_authorization_consequence(self):
        # Someone hitting this needs to know it is not a cosmetic toggle.
        stop = RUN[RUN.index('the policy editor is ON on this host'):][:1200]
        self.assertIn('$MCP_POLICY_FILE', stop,
                      "the refusal should name the policy file that stops being read")

    def test_enabling_is_still_a_flag_and_never_a_site_env_key(self):
        # The guard must not have been implemented by making the editor
        # configurable from site.env, which would be the easy wrong fix.
        self.assertIn('MCP_AUTHZ_EDITOR is set in $SITE_ENV, and it is not settable there',
                      RUN)


if __name__ == "__main__":
    unittest.main()
