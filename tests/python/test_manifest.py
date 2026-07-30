"""Unit tests for the install manifest the client installers write.

The manifest is what turns uninstall into a restore rather than a guess: it
records what an install run created, which packages it installed as opposed to
found already present, which files it replaced and where the original went, and
the prior value of every settings key it touched. All installers share one
merge implementation, `install-bridge.sh --manifest-merge`, and these tests
drive it through subprocess the same way the repo already tests scripts.
Run:  python -m unittest -v  (from tests/python)"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
INSTALLER = os.path.join(REPO, 'client', 'install-bridge.sh').replace(os.sep, '/')
SH = shutil.which('sh')


def merge(path, frag):
    """One --manifest-merge run; frag goes in as the JSON the installers build."""
    return subprocess.run(
        [SH, INSTALLER, '--manifest-merge', path.replace(os.sep, '/'), json.dumps(frag)],
        capture_output=True, text=True)


def read(path):
    with open(path) as f:
        return json.load(f)


@unittest.skipIf(SH is None, 'no POSIX sh on PATH')
class ManifestMerge(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.td, ignore_errors=True)
        self.path = os.path.join(self.td, 'install-manifest.json')

    def test_manifest_parses_and_carries_version(self):
        r = merge(self.path, {'written_by': 'install-bridge.sh',
                              'created': ['/opt/mcp-krb/mcp-krb-bridge.py']})
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = read(self.path)
        self.assertEqual(doc['manifest_version'], 1)
        self.assertEqual(doc['written_by'], 'install-bridge.sh')
        self.assertIn('/opt/mcp-krb/mcp-krb-bridge.py', doc['created'])

    def test_second_install_does_not_overwrite_replaced_backup(self):
        # The first backup is the pristine original; a re-run that backed up
        # again would be backing up this kit's own file over it.
        merge(self.path, {'replaced': {'/etc/krb5.conf': '/opt/mcp-krb/backup/krb5.conf'}})
        merge(self.path, {'replaced': {'/etc/krb5.conf': '/opt/mcp-krb/backup/second-run'}})
        doc = read(self.path)
        self.assertEqual(doc['replaced']['/etc/krb5.conf'],
                         '/opt/mcp-krb/backup/krb5.conf')

    def test_already_present_is_never_reclassified_as_installed(self):
        # Only packages_installed may ever be removed. A machine that already
        # had krb5-user must keep it no matter what a later run reports.
        merge(self.path, {'packages_already_present': ['krb5-user']})
        merge(self.path, {'packages_installed': ['krb5-user']})
        doc = read(self.path)
        self.assertIn('krb5-user', doc['packages_already_present'])
        self.assertNotIn('krb5-user', doc['packages_installed'])

    def test_installed_is_never_reclassified_as_present(self):
        # The reverse guard: run two finds the package present because run one
        # installed it. Moving it to already-present would strand it.
        merge(self.path, {'packages_installed': ['krb5-user']})
        merge(self.path, {'packages_already_present': ['krb5-user']})
        doc = read(self.path)
        self.assertIn('krb5-user', doc['packages_installed'])
        self.assertNotIn('krb5-user', doc['packages_already_present'])

    def test_created_merges_as_a_set(self):
        merge(self.path, {'created': ['/opt/mcp-krb/mcp-krb-bridge.py']})
        merge(self.path, {'created': ['/opt/mcp-krb/mcp-krb-bridge.py',
                                      '/etc/claude-code/managed-mcp.json']})
        doc = read(self.path)
        self.assertEqual(doc['created'].count('/opt/mcp-krb/mcp-krb-bridge.py'), 1)
        self.assertIn('/etc/claude-code/managed-mcp.json', doc['created'])

    def test_prior_values_keep_the_first_record(self):
        # null means the key was absent before the kit ever touched it, so
        # uninstall deletes it; a string is the user's own raw JSON scalar,
        # restored verbatim. Either way the first run's record wins.
        merge(self.path, {'prior_values': {'remote.SSH.path': None,
                                           'remote.SSH.useLocalServer': 'true'}})
        merge(self.path, {'prior_values': {'remote.SSH.path': '"C:\\\\kit\\\\own.bat"'}})
        doc = read(self.path)
        self.assertIn('remote.SSH.path', doc['prior_values'])
        self.assertIsNone(doc['prior_values']['remote.SSH.path'])
        self.assertEqual(doc['prior_values']['remote.SSH.useLocalServer'], 'true')

    def test_corrupt_manifest_is_refused_not_overwritten(self):
        # A corrupt record is still evidence; replacing it would turn the next
        # uninstall into guesswork.
        with open(self.path, 'w') as f:
            f.write('{not json')
        r = merge(self.path, {'created': ['/opt/mcp-krb/mcp-krb-bridge.py']})
        self.assertNotEqual(r.returncode, 0)
        with open(self.path) as f:
            self.assertEqual(f.read(), '{not json')

    def test_non_json_fragment_is_refused(self):
        r = subprocess.run(
            [SH, INSTALLER, '--manifest-merge', self.path.replace(os.sep, '/'), '{broken'],
            capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(self.path))


if __name__ == '__main__':
    unittest.main()
