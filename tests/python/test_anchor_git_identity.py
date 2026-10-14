"""install-anchor.sh keeps git's global user.email equal to the address IPA has.

A commit carries whatever address git is configured with, and the forges credit
it by that address; a push through Gitea and its mirror changes nothing in it.
So the anchor, which the kinit wrappers run on every ticket, sets the global
user.email from the IPA record it already reads for the uid.

These run the real script against a throwaway HOME with fake klist, curl,
systemctl and launchctl. The anchor is made to look already set up (the ssh
block present, the units active), which is the path every kinit after the first
takes, so the script stops right after the identity step and never installs
anything. Kinit wrappers return this script's status, so the step must stay
silent and successful when IPA cannot be read.
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANCHOR = ROOT / "client" / "install-anchor.sh"
SH = shutil.which("sh")
GIT = shutil.which("git")

FAKE_KLIST = """#!/bin/sh
echo "Default principal: alice@EXAMPLE.INTERNAL"
"""

# Answers as IPA would: the login status for the -w call, the record otherwise.
FAKE_CURL = """#!/bin/sh
case " $* " in
    *" -w "*) printf '%s' "${IPA_LOGIN_CODE:-200}" ;;
    *) printf '%s' "$IPA_JSON" ;;
esac
"""

# Every unit "active", every other call a no-op: nothing real is ever touched.
FAKE_SYSTEMCTL = """#!/bin/sh
exit 0
"""
FAKE_LAUNCHCTL = """#!/bin/sh
[ "$1" = list ] && printf '%s\\n' com.overpassconnect.mcp-krb.anchor-mcp \\
    com.overpassconnect.mcp-krb.anchor-fetch com.overpassconnect.mcp-krb.anchor-git
exit 0
"""

RECORD = {"result": {"result": {"uidnumber": ["1337600016"],
                                "mail": ["alice@example.internal"],
                                "givenname": ["Alice"], "sn": ["Doe"]}}}


@unittest.skipIf(SH is None or GIT is None or os.name == "nt",
                 "needs sh and git; Windows runs the anchor inside WSL")
@unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                 "install-anchor.sh refuses to run as root")
class GitIdentityFollowsIpa(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.home = self.td / "home"
        appdir = self.home / "Library" / "Application Support" / "mcp-krb"
        appdir.mkdir(parents=True)
        (appdir / "mcp-krb-bridge.py").write_text("")
        ssh = self.home / ".ssh"
        ssh.mkdir()
        (ssh / "config").write_text("# BEGIN mcp-krb-anchor\nHost *.example.internal\n"
                                    "# END mcp-krb-anchor\n")
        bindir = self.td / "bin"
        bindir.mkdir()
        for name, body in (("klist", FAKE_KLIST), ("curl", FAKE_CURL),
                           ("systemctl", FAKE_SYSTEMCTL), ("launchctl", FAKE_LAUNCHCTL)):
            p = bindir / name
            p.write_text(body)
            p.chmod(0o755)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / ".config"),
                        GIT_CONFIG_NOSYSTEM="1", IPA_JSON=json.dumps(RECORD),
                        PATH=str(bindir) + os.pathsep + os.environ["PATH"])

    def git(self, *args):
        r = subprocess.run([GIT, "config", "--global"] + list(args), env=self.env,
                           capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    def run_anchor(self, *extra):
        return subprocess.run(
            [SH, str(ANCHOR), "--mcp-url", "https://mcp.example.internal/",
             "--domain", "example.internal", "--ipa-url", "https://ipa.example.internal"]
            + list(extra), env=self.env, capture_output=True, text=True)

    def test_replaces_the_address_and_keeps_the_old_one(self):
        self.git("user.email", "old@example.org")
        self.git("user.name", "Alice Q")
        r = self.run_anchor()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.git("--get", "user.email"), "alice@example.internal")
        self.assertEqual(self.git("--get", "mcp-krb.priorUserEmail"), "old@example.org")
        self.assertEqual(self.git("--get", "user.name"), "Alice Q", "a set name is left alone")
        self.assertIn("user.email set to alice@example.internal", r.stdout)

    def test_silent_when_it_already_matches(self):
        self.git("user.email", "alice@example.internal")
        self.git("user.name", "Alice Q")
        r = self.run_anchor()
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))

    def test_fills_the_name_only_when_none_is_set(self):
        self.run_anchor()
        self.assertEqual(self.git("--get", "user.name"), "Alice Doe")

    def test_ipa_down_changes_nothing_and_fails_nothing(self):
        self.git("user.email", "old@example.org")
        self.env["IPA_LOGIN_CODE"] = "401"
        r = self.run_anchor()
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))
        self.assertEqual(self.git("--get", "user.email"), "old@example.org")

    def test_a_record_without_an_address_changes_nothing(self):
        self.git("user.email", "old@example.org")
        rec = json.loads(json.dumps(RECORD))
        del rec["result"]["result"]["mail"]
        self.env["IPA_JSON"] = json.dumps(rec)
        r = self.run_anchor()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.git("--get", "user.email"), "old@example.org")

    def test_dry_run_only_says_what_it_would_do(self):
        self.git("user.email", "old@example.org")
        r = self.run_anchor("--dry-run")
        self.assertIn("would: set git user.email to alice@example.internal", r.stdout)
        self.assertEqual(self.git("--get", "user.email"), "old@example.org")

    def test_uninstall_puts_the_old_address_back(self):
        self.git("user.email", "old@example.org")
        self.run_anchor()
        r = subprocess.run([SH, str(ANCHOR), "--uninstall"], env=self.env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.git("--get", "user.email"), "old@example.org")
        self.assertIsNone(self.git("--get", "mcp-krb.priorUserEmail"))

    def test_uninstall_unsets_an_address_that_was_never_there(self):
        self.run_anchor()
        subprocess.run([SH, str(ANCHOR), "--uninstall"], env=self.env,
                       capture_output=True, text=True)
        self.assertIsNone(self.git("--get", "user.email"))


if __name__ == "__main__":
    unittest.main()
