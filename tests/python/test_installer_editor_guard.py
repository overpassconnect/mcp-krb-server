"""The policy editor is a site.env key, and the installer must converge on it.

run.sh cannot be driven from a unit test: it needs root, a real systemd, a real
keytab and a live KDC. So this reads the script rather than running it. That is
weaker than a behavioural test and worth stating plainly; what it defends
against is the realistic regression, which is the setting drifting back into an
invocation flag during an edit.

History, because the shape here is a reversal and the reasons matter.

MCP_AUTHZ_EDITOR was once a flag, --enable-authz-editor, and refused outright if
it appeared in site.env. The reasoning was that the editor is an authenticated
write surface over tool authorization, so enabling it should be a person's
decision rather than a parameter file's.

That reasoning did not hold. site.env is 0640 root:root on the host and nothing
writes it automatically, so setting the key and passing the flag require exactly
the same privilege: root on that machine. The flag gated nothing the file did
not already gate.

It did cost. Living only in the invocation, the state was recorded nowhere, so a
host rebuilt from site.env came up WITHOUT the editor and nothing said so. And a
plain re-run, which is how every other setting converges, silently switched it
OFF. That happened on a live host: a routine re-run to deploy an unrelated fix
took the editor down, and the only symptom was a 404 on a page nobody had open.

That consequence was not cosmetic. With the editor off the server stops reading
the policy overlay, so the reviewed in-code defaults become the live policy and
every tool the overlay was managing silently changes hands. The file itself was
never touched, which is what made it hard to see: the policy was intact and
unread.

As a key, a re-run reads the same file and converges, so that failure cannot
happen, and the state is somewhere it can be reviewed and reproduced.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "server" / "install"
RUN = (INSTALL / "run.sh").read_text(encoding="utf-8")
EXAMPLE = (INSTALL / "site.env.example").read_text(encoding="utf-8")


class TheSettingIsAKey(unittest.TestCase):

    def test_the_flags_are_gone_from_the_argument_parser(self):
        # A stray case arm would give two ways to set one thing, and they would
        # eventually disagree.
        for flag in ("--enable-authz-editor", "--disable-authz-editor"):
            self.assertNotRegex(
                RUN, r"\n\s*%s\)" % re.escape(flag),
                "%s is back in the argument parser" % flag)

    def test_site_env_is_no_longer_refused_for_carrying_the_key(self):
        self.assertNotIn(
            'MCP_AUTHZ_EDITOR is set in $SITE_ENV, and it is not settable there',
            RUN,
            "the installer still rejects the key it is now supposed to read")

    def test_the_key_is_parsed_into_one_variable(self):
        self.assertRegex(
            RUN, r'case "\$\(printf .%s. "\$\{MCP_AUTHZ_EDITOR:-\}"',
            "MCP_AUTHZ_EDITOR is not parsed from site.env any more")
        self.assertIn("AUTHZ_EDITOR_ON=1", RUN)
        self.assertIn("AUTHZ_EDITOR_ON=0", RUN)

    def test_an_unparseable_value_is_refused_rather_than_guessed(self):
        # Defaulting either way is wrong: guessing "off" silently disables an
        # authorization surface, guessing "on" silently serves one.
        self.assertIn("neither\n  on nor off", RUN)

    def test_the_example_documents_the_key_and_defaults_it_off(self):
        self.assertRegex(EXAMPLE, r"(?m)^MCP_AUTHZ_EDITOR=off\s*$",
                         "site.env.example should ship the key, defaulted off")

    def test_enabling_still_requires_admins(self):
        # An editor with no admins authenticates everyone and authorises nobody,
        # and the only way to discover that is to open it.
        self.assertIn("MCP_AUTHZ_EDITOR is on, so $SITE_ENV needs MCP_POLICY_ADMINS", RUN)

    def test_the_state_directory_is_still_tied_to_the_editor(self):
        # ProtectSystem=strict makes everything else read-only, so without the
        # state directory the editor starts, authenticates, and fails only when
        # somebody tries to save.
        self.assertIn("StateDirectory=mcp-server", RUN)


if __name__ == "__main__":
    unittest.main()
