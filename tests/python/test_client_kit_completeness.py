"""The client kit has to agree with itself across four files.

Adding a file to the kit means touching install-bridge.sh (Linux), setup-macos.sh
(macOS), run.sh (what the publisher serves) and uninstall.sh (what may be
removed). Miss one and the failure is quiet and late: the installer 404s
partway through provisioning a workstation, or the file installs fine and then
outlives every attempt to remove it.

That happened. --fetch, the remote bridge and mcp-fetch were written, tested and
merged while no installer placed any of them, so they existed in the repository
and on no machine. These tests are the check that would have said so.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALL = (ROOT / "client" / "install-bridge.sh").read_text(encoding="utf-8")
MACOS = (ROOT / "client" / "setup-macos.sh").read_text(encoding="utf-8")
UNINSTALL = (ROOT / "client" / "uninstall.sh").read_text(encoding="utf-8")
RUN = (ROOT / "server" / "install" / "run.sh").read_text(encoding="utf-8")
VERIFY = (ROOT / "server" / "install" / "verify.sh").read_text(encoding="utf-8")

# What the bridge directory ships. __pycache__ and examples are not payload.
SHIPPED = sorted(
    p.name for p in (ROOT / "client" / "bridge").iterdir()
    if p.is_file() and not p.name.startswith(".")
)


def bundle_files():
    m = re.search(r'BUNDLE_FILES="([^"]*)"', RUN)
    assert m, "BUNDLE_FILES not found in run.sh"
    return [f.split("/")[-1] for f in m.group(1).split()]


def macos_fetch_list():
    # The literal `for f in ... ; do` list setup-macos.sh curls one by one.
    # Parsed, not substring-searched: "mcp-krb" is a substring of
    # "mcp-krb-bridge.py", so a plain `in` over the whole file green-lit a
    # launcher the Mac never fetched. Exact tokens only.
    for line in MACOS.splitlines():
        if "for f in" in line and "mcp-krb-bridge.py" in line:
            return line.split("for f in", 1)[1].split(";", 1)[0].split()
    raise AssertionError("setup-macos.sh bridge fetch loop not found")


class TestEverythingShippedIsPublished(unittest.TestCase):

    def test_the_bridge_directory_is_not_empty(self):
        # A glob that matches nothing would make the rest of this file vacuous.
        self.assertIn("mcp-krb-bridge.py", SHIPPED)
        self.assertGreaterEqual(len(SHIPPED), 3)

    def test_every_file_in_the_bridge_directory_is_in_the_bundle(self):
        missing = [f for f in SHIPPED if f not in bundle_files()]
        self.assertEqual([], missing,
                         "client/bridge holds files the publisher never serves, so a "
                         "workstation asking for them gets a 404 mid-install")

    def test_verify_checks_each_published_bridge_file(self):
        for name in SHIPPED:
            self.assertIn(name, VERIFY,
                          "%s is served but verify.sh never confirms it is "
                          "reachable" % name)

    def test_every_top_level_client_script_is_published(self):
        # Not just the installers. uninstall.sh and uninstall.ps1 sat in the
        # repository unserved for months while both installers wrote the
        # manifests only they can read, so the reversal existed nowhere a
        # provisioned workstation could reach it and the only way off a machine
        # was to clone the source. Publishing an installer without its
        # uninstaller is a one-way door, and nothing failed to say so.
        scripts = sorted(
            p.name for p in (ROOT / "client").iterdir()
            if p.is_file() and p.suffix in (".sh", ".ps1"))
        self.assertIn("uninstall.sh", scripts)      # anti-vacuity
        missing = [s for s in scripts if s not in bundle_files()]
        self.assertEqual([], missing,
                         "client/ holds scripts the publisher never serves, so a "
                         "workstation cannot fetch them: %s" % missing)


class TestEverythingInstalledCanBeRemoved(unittest.TestCase):
    """Anything the installer records as created must be a path uninstall owns."""

    def owned(self, path):
        # uninstall.sh's path_is_ours, read out of the script rather than
        # restated here, so widening one without the other is caught.
        block = UNINSTALL[UNINSTALL.index("path_is_ours()"):UNINSTALL.index("if [ \"$YES\" = 1 ]")]
        if path.startswith("/opt/mcp-krb"):
            return '"$APPROOT"|"$APPROOT"/*' in block
        return path in block

    def test_the_paths_install_bridge_records_are_all_removable(self):
        # Everything install-bridge.sh puts in the manifest's created list. The
        # slice runs to the end of the file rather than to the merge_manifest
        # call, because the function is defined long before it is used.
        frag = INSTALL[INSTALL.index("FRAG_CREATED="):]
        names = set(re.findall(r'\$DEST/\$(\w+)', frag))
        self.assertTrue(names, "no $DEST entries found; did the manifest change shape?")
        for var in names:
            m = re.search(r'^%s="([^"]+)"' % var, INSTALL, re.M)
            self.assertTrue(m, "%s is recorded but never defined" % var)
            self.assertTrue(self.owned("/opt/mcp-krb/" + m.group(1)))

        # Literal paths outside $DEST, which are the ones that need an explicit
        # allowlist entry rather than falling under the kit tree.
        for m in re.finditer(r'^(\w*LINK\w*)="(/[^"]+)"', INSTALL, re.M):
            self.assertTrue(self.owned(m.group(2)),
                            "%s is created outside the kit tree and uninstall.sh "
                            "would refuse to remove it" % m.group(2))


class TestFirefoxProvisioning(unittest.TestCase):
    """setup.ps1 installs a browser inside WSL, because on Windows there is no
    other way to answer a Negotiate challenge: the machine holds no ticket
    outside WSL, so a Windows browser prompts for a password forever.
    """

    SETUP = (ROOT / "client" / "setup.ps1").read_text(encoding="utf-8")

    def test_delegation_uris_is_never_set(self):
        # This pref forwards the TGT to the listed hosts. Setting it would undo
        # the single property the whole design rests on, and it is one word away
        # from the pref that IS set, so it is worth a test rather than a comment.
        #
        # The name appears in a comment saying why it is absent, so assert on the
        # dict-key form that would actually set it, not on the mention.
        self.assertIn("'network.negotiate-auth.trusted-uris':", self.SETUP)
        self.assertNotIn("'network.negotiate-auth.delegation-uris':", self.SETUP)

    def test_the_signing_key_is_pinned_and_checked_before_use(self):
        # Adding an APT repo is adding a party that can put root-run code on the
        # machine. The fingerprint has to be verified before the repo exists,
        # not after.
        self.assertIn("35BAA0B33E9EB396F59CA838C0BA5CE6DC6315A3", self.SETUP)
        blk = self.SETUP[self.SETUP.index("ff_step() {"):self.SETUP.index("ff_step\n")]
        check = blk.index("FF-KEY-MISMATCH")
        add_repo = blk.index("sources.list.d/mozilla.list")
        self.assertLess(check, add_repo,
                        "the repository is added before the key is verified")
        self.assertIn("rm -f /etc/apt/keyrings/packages.mozilla.org.asc", blk,
                      "a mismatched key must not be left on disk")

    def test_it_can_be_skipped(self):
        self.assertIn("$SkipFirefox", self.SETUP)

    def test_everything_it_creates_can_be_uninstalled(self):
        # The same parity rule as the rest of the kit: a path recorded in the
        # manifest that uninstall.sh does not own is a file that outlives the
        # kit forever.
        frag = self.SETUP[self.SETUP.index("if env.get('FF_NEW')"):]
        frag = frag[:frag.index("doc = {}")]
        paths = re.findall(r"'(/etc/[^']+)'", frag)
        self.assertGreaterEqual(len(paths), 4, "expected the repo, pin, keyring and policy dir")
        block = UNINSTALL[UNINSTALL.index("path_is_ours()"):UNINSTALL.index('if [ "$YES" = 1 ]')]
        for p in paths:
            with self.subTest(path=p):
                stem = p.rsplit("/", 1)[0]
                self.assertTrue(p in block or (stem + "/*") in block,
                                "%s is created but uninstall.sh would refuse to remove it" % p)

    def test_the_policy_is_written_as_real_json(self):
        # Hand-built JSON in a shell heredoc is how a policy file ends up
        # syntactically valid but semantically empty, and Firefox ignores a
        # malformed one silently.
        blk = self.SETUP[self.SETUP.index("ff_step() {"):self.SETUP.index("ff_step\n")]
        self.assertIn("json.dump", blk)


class TestMacOsInstallsTheSameKit(unittest.TestCase):

    def test_macos_fetches_every_bridge_file(self):
        # A Mac gets the files individually rather than through
        # install-bridge.sh, which is exactly how it fell a file behind.
        fetched = macos_fetch_list()
        for name in SHIPPED:
            self.assertIn(name, fetched,
                          "setup-macos.sh never fetches %s, so a Mac ends up with "
                          "a partial kit" % name)

    def test_macos_records_what_it_fetches(self):
        block = MACOS[MACOS.index("mkdir -p \"$APPDIR\"; note_created_dir"):]
        block = block[:block.index("PY=\"$APPDIR/venv/bin/python3\"")]
        self.assertIn("note_created", block,
                      "files fetched without note_created survive uninstall")


if __name__ == "__main__":
    unittest.main()
