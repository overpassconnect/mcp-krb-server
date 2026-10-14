"""install-anchor.sh gives realm repositories the identity IPA has, and only them.

A commit carries whatever name and address git is configured with, and the
forges credit it by that address; a push through Gitea and its mirror changes
nothing in it. So the anchor, which the kinit wrappers run on every ticket,
writes the name and address from the IPA record it already reads for the uid
into a file of its own, and puts one includeIf in the global git config that
makes git read that file in a repository with a remote under
https://*.<domain>/. The global user.email and user.name are left alone.

These run the real script against a throwaway HOME with fake klist, curl,
systemctl and launchctl. The anchor is made to look already set up (the ssh
block present, the units active), which is the path every kinit after the first
takes, so the script stops right after the identity step and never installs
anything. Kinit wrappers return this script's status, so the step must stay
silent and successful when IPA cannot be read. The Windows side (--windows-git)
runs against fake git.exe, cmd.exe and wslpath, with a second HOME standing in
for the Windows profile.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANCHOR = ROOT / "client" / "install-anchor.sh"
SH = shutil.which("sh")
GIT = shutil.which("git")


def git_reads_hasconfig():
    if GIT is None:
        return False
    m = re.match(r"git version (\d+)\.(\d+)", subprocess.run(
        [GIT, "version"], capture_output=True, text=True).stdout)
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (2, 36)


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

# The Windows side. cmd.exe answers %USERPROFILE% with CRLF, as it does; wslpath
# maps C:/... under WIN_ROOT/c/...; git.exe is the real git with the Windows
# profile as its HOME, so its --global config is a separate file.
FAKE_CMD = """#!/bin/sh
printf '%s\\r\\n' "${WIN_USERPROFILE-C:\\\\Users\\\\Win User}"
"""
FAKE_WSLPATH = """#!/bin/sh
[ "$1" = -u ] && shift
p="$(printf '%s' "$1" | tr '\\\\' '/')"
d="$(printf '%s' "$p" | cut -c1 | tr 'A-Z' 'a-z')"
printf '%s/%s%s\\n' "$WIN_ROOT" "$d" "${p#?:}"
"""
FAKE_GIT_EXE = """#!/bin/sh
HOME="$WIN_ROOT/c/Users/Win User" XDG_CONFIG_HOME="$WIN_ROOT/c/Users/Win User/.config" \\
    exec "{git}" "$@"
"""
# A git that says it is 2.34, which predates includeIf hasconfig.
FAKE_OLD_GIT = """#!/bin/sh
[ "$1" = version ] && { echo "git version 2.34.1"; exit 0; }
exec "{git}" "$@"
"""

RECORD = {"result": {"result": {"uidnumber": ["1337600016"],
                                "mail": ["alice@example.internal"],
                                "givenname": ["Alice"], "sn": ["Doe"]}}}
INCLUDE = "includeIf.hasconfig:remote.*.url:https://*.example.internal/**.path"
WIN_IDFILE = "C:/Users/Win User/.config/mcp-krb/git-identity.gitconfig"


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
        self.idfile = self.home / ".config" / "mcp-krb" / "git-identity.gitconfig"
        self.win_root = self.td / "win"
        self.win_home = self.win_root / "c" / "Users" / "Win User"
        self.win_home.mkdir(parents=True)
        self.bindir = self.td / "bin"
        self.bindir.mkdir()
        for name, body in (("klist", FAKE_KLIST), ("curl", FAKE_CURL),
                           ("systemctl", FAKE_SYSTEMCTL), ("launchctl", FAKE_LAUNCHCTL)):
            self.fake(name, body)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update(HOME=str(self.home), XDG_CONFIG_HOME=str(self.home / ".config"),
                        GIT_CONFIG_NOSYSTEM="1", IPA_JSON=json.dumps(RECORD),
                        WIN_ROOT=str(self.win_root),
                        PATH=str(self.bindir) + os.pathsep + os.environ["PATH"])

    def fake(self, name, body):
        p = self.bindir / name
        p.write_text(body.replace("{git}", GIT))
        p.chmod(0o755)

    def with_windows(self):
        for name, body in (("cmd.exe", FAKE_CMD), ("wslpath", FAKE_WSLPATH),
                           ("git.exe", FAKE_GIT_EXE)):
            self.fake(name, body)

    def git(self, *args, cmd="git"):
        r = subprocess.run([str(self.bindir / cmd) if cmd != "git" else GIT,
                            "config", "--global"] + list(args),
                           env=self.env, capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    def repo(self, url):
        r = self.td / ("repo%d" % len(list(self.td.glob("repo*"))))
        subprocess.run([GIT, "init", "-q", str(r)], env=self.env, check=True)
        subprocess.run([GIT, "-C", str(r), "remote", "add", "origin", url],
                       env=self.env, check=True)
        return r

    def in_repo(self, repo, key):
        r = subprocess.run([GIT, "-C", str(repo), "config", key], env=self.env,
                           capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    def run_anchor(self, *extra):
        return subprocess.run(
            [SH, str(ANCHOR), "--mcp-url", "https://mcp.example.internal/",
             "--domain", "example.internal", "--ipa-url", "https://ipa.example.internal"]
            + list(extra), env=self.env, capture_output=True, text=True)

    def uninstall(self, *extra):
        return subprocess.run([SH, str(ANCHOR), "--uninstall"] + list(extra), env=self.env,
                              capture_output=True, text=True)

    def test_writes_the_identity_and_one_include_and_leaves_the_global_alone(self):
        self.git("user.email", "old@example.org")
        self.git("user.name", "Alice Q")
        r = self.run_anchor()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.git("--get", "user.email"), "old@example.org")
        self.assertEqual(self.git("--get", "user.name"), "Alice Q")
        self.assertEqual(self.git("--get-all", INCLUDE), str(self.idfile))
        ident = ["git", "config", "-f", str(self.idfile)]
        self.assertEqual(subprocess.run(ident + ["user.email"], capture_output=True,
                                        text=True, env=self.env).stdout.strip(),
                         "alice@example.internal")
        self.assertEqual(subprocess.run(ident + ["user.name"], capture_output=True,
                                        text=True, env=self.env).stdout.strip(), "Alice Doe")
        self.assertIn("commit as Alice Doe <alice@example.internal>", r.stdout)

    @unittest.skipUnless(git_reads_hasconfig(), "this git predates includeIf hasconfig")
    def test_realm_repositories_commit_as_ipa_says_and_others_as_before(self):
        self.git("user.email", "old@example.org")
        self.git("user.name", "Alice Q")
        self.run_anchor()
        realm = self.repo("https://git.example.internal/org/repo.git")
        other = self.repo("https://github.com/org/repo.git")
        self.assertEqual(self.in_repo(realm, "user.email"), "alice@example.internal")
        self.assertEqual(self.in_repo(realm, "user.name"), "Alice Doe")
        self.assertEqual(self.in_repo(other, "user.email"), "old@example.org")
        self.assertEqual(self.in_repo(other, "user.name"), "Alice Q")

    def test_silent_when_already_in_place(self):
        self.run_anchor()
        r = self.run_anchor()
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))

    @unittest.skipUnless(git_reads_hasconfig(), "this git predates includeIf hasconfig")
    def test_moves_the_include_below_a_user_section_added_after_it(self):
        self.run_anchor()
        # With no [user] in the file, this appends one after the include, and
        # git's last-one-wins would hand realm repositories the global address.
        self.git("user.email", "personal@example.org")
        realm = self.repo("https://git.example.internal/org/repo.git")
        self.assertEqual(self.in_repo(realm, "user.email"), "personal@example.org")
        r = self.run_anchor()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.in_repo(realm, "user.email"), "alice@example.internal")
        self.assertEqual(self.git("--get-all", INCLUDE), str(self.idfile), "exactly one entry")
        self.assertEqual(self.git("--get", "user.email"), "personal@example.org")

    def test_ipa_down_changes_nothing_and_fails_nothing(self):
        self.git("user.email", "old@example.org")
        self.env["IPA_LOGIN_CODE"] = "401"
        r = self.run_anchor()
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))
        self.assertFalse(self.idfile.exists())
        self.assertIsNone(self.git("--get-all", INCLUDE))

    def test_a_record_without_an_address_changes_nothing(self):
        rec = json.loads(json.dumps(RECORD))
        del rec["result"]["result"]["mail"]
        self.env["IPA_JSON"] = json.dumps(rec)
        r = self.run_anchor()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.idfile.exists())
        self.assertIsNone(self.git("--get-all", INCLUDE))

    def test_dry_run_only_says_what_it_would_do(self):
        r = self.run_anchor("--dry-run")
        self.assertIn("would: write Alice Doe <alice@example.internal>", r.stdout)
        self.assertIn("would: add an includeIf", r.stdout)
        self.assertFalse(self.idfile.exists())
        self.assertIsNone(self.git("--get-all", INCLUDE))

    def test_undoes_the_global_address_an_earlier_version_set(self):
        self.git("user.email", "alice@example.internal")
        self.git("mcp-krb.priorUserEmail", "old@example.org")
        r = self.run_anchor()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.git("--get", "user.email"), "old@example.org")
        self.assertIsNone(self.git("--get", "mcp-krb.priorUserEmail"))
        self.assertIn("put back to old@example.org", r.stdout)

    def test_keeps_a_global_address_changed_by_hand_since(self):
        self.git("user.email", "mine@example.org")
        self.git("mcp-krb.priorUserEmail", "old@example.org")
        self.run_anchor()
        self.assertEqual(self.git("--get", "user.email"), "mine@example.org")
        self.assertIsNone(self.git("--get", "mcp-krb.priorUserEmail"))

    def test_uninstall_removes_only_what_it_wrote(self):
        self.git("user.email", "old@example.org")
        mine = "includeIf.hasconfig:remote.*.url:https://git.example.org/**.path"
        self.git(mine, "/somewhere/else.gitconfig")
        self.run_anchor()
        r = self.uninstall()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIsNone(self.git("--get-all", INCLUDE))
        self.assertFalse(self.idfile.exists())
        self.assertEqual(self.git("--get", mine), "/somewhere/else.gitconfig")
        self.assertEqual(self.git("--get", "user.email"), "old@example.org")
        self.assertNotIn("includeIf \"hasconfig:remote.*.url:https://*.example.internal",
                         (self.home / ".gitconfig").read_text(), "no empty section left")

    def test_uninstall_still_puts_back_what_an_earlier_version_replaced(self):
        self.git("user.email", "alice@example.internal")
        self.git("mcp-krb.priorUserEmail", "old@example.org")
        r = self.uninstall()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.git("--get", "user.email"), "old@example.org")

    def test_a_git_older_than_2_36_is_warned_about(self):
        self.fake("git", FAKE_OLD_GIT)
        r = self.run_anchor()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("predates includeIf hasconfig", r.stderr)
        self.assertEqual(self.run_anchor().stderr, "", "warned when it writes, not every kinit")

    def test_windows_git_gets_the_same_identity(self):
        self.with_windows()
        r = self.run_anchor("--windows-git")
        self.assertEqual(r.returncode, 0, r.stderr)
        win_copy = self.win_home / ".config" / "mcp-krb" / "git-identity.gitconfig"
        self.assertEqual(win_copy.read_bytes(), self.idfile.read_bytes())
        self.assertEqual(self.git("--get-all", INCLUDE, cmd="git.exe"), WIN_IDFILE)
        self.assertIn("git (Windows): repositories under https://*.example.internal/", r.stdout)
        again = self.run_anchor("--windows-git")
        self.assertEqual((again.returncode, again.stdout, again.stderr), (0, "", ""))

    def test_uninstall_takes_it_out_of_windows_git_too(self):
        self.with_windows()
        self.git(INCLUDE, "C:/elsewhere.gitconfig", cmd="git.exe")
        self.run_anchor("--windows-git")
        r = self.uninstall("--windows-git")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.git("--get-all", INCLUDE, cmd="git.exe"), "C:/elsewhere.gitconfig")
        self.assertFalse((self.win_home / ".config" / "mcp-krb").exists())

    def test_windows_out_of_reach_is_reported_once(self):
        self.with_windows()
        self.env["WIN_USERPROFILE"] = "UNC paths are not supported."
        r = self.run_anchor("--windows-git")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Windows git keeps its own identity", r.stderr)
        again = self.run_anchor("--windows-git")
        self.assertEqual((again.returncode, again.stdout, again.stderr), (0, "", ""))


if __name__ == "__main__":
    unittest.main()
