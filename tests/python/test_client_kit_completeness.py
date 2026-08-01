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


class TestMacOsInstallsTheSameKit(unittest.TestCase):

    def test_macos_fetches_every_bridge_file(self):
        # A Mac gets the files individually rather than through
        # install-bridge.sh, which is exactly how it fell a file behind.
        for name in SHIPPED:
            self.assertIn(name, MACOS,
                          "setup-macos.sh never fetches %s, so a Mac ends up with "
                          "a partial kit" % name)

    def test_macos_records_what_it_fetches(self):
        block = MACOS[MACOS.index("mkdir -p \"$APPDIR\"; note_created_dir"):]
        block = block[:block.index("PY=\"$APPDIR/venv/bin/python3\"")]
        self.assertIn("note_created", block,
                      "files fetched without note_created survive uninstall")


if __name__ == "__main__":
    unittest.main()
