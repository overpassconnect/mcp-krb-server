"""Unit tests for client/uninstall.sh.

The script is driven through subprocess against a synthetic filesystem tree
and manifest (its --root test hook), the way the repo already tests scripts.
The invariant test at the bottom is a guard, not a formality: un-enrolment is
a realm-side, irreversible-from-the-workstation change, and the cheapest way
to stop a refactor from folding it into uninstall is to assert no code path
ever calls it.
Run:  python -m unittest -v  (from tests/python)"""
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..'))
UNINSTALL = os.path.join(REPO, 'client', 'uninstall.sh').replace(os.sep, '/')
SH = shutil.which('sh')

MANIFEST = {
    'manifest_version': 1,
    'written_by': 'install-bridge.sh',
    'created': ['/opt/mcp-krb/mcp-krb-bridge.py',
                '/etc/claude-code/managed-mcp.json',
                '/usr/local/share/ca-certificates/realm-ca.crt'],
    'created_dirs': ['/opt/mcp-krb', '/etc/claude-code'],
    'packages_installed': ['python3-gssapi'],
    'packages_already_present': ['krb5-user'],
    'replaced': {'/etc/krb5.conf': '/opt/mcp-krb/backup/krb5.conf'},
    'prior_values': {},
}


@unittest.skipIf(SH is None, 'no POSIX sh on PATH')
class UninstallSh(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def path(self, rel):
        return os.path.join(self.root, rel.replace('/', os.sep).lstrip(os.sep))

    def put(self, rel, content=''):
        p = self.path(rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w') as f:
            f.write(content)
        return p

    def make_tree(self, manifest=MANIFEST):
        self.put('opt/mcp-krb/mcp-krb-bridge.py', '# bridge')
        self.put('opt/mcp-krb/backup/krb5.conf', 'THE PRISTINE ORIGINAL')
        self.put('etc/krb5.conf', 'THE KIT VERSION')
        self.put('etc/claude-code/managed-mcp.json', '{"mcpServers":{"internal-tools":{}}}')
        self.put('usr/local/share/ca-certificates/realm-ca.crt', 'CA')
        if manifest is not None:
            self.put('opt/mcp-krb/install-manifest.json', json.dumps(manifest))

    def run_uninstall(self, *args, path_prefix=None):
        env = dict(os.environ)
        if path_prefix:
            env['PATH'] = path_prefix + os.pathsep + env.get('PATH', '')
        return subprocess.run(
            [SH, UNINSTALL, '--root', self.root.replace(os.sep, '/')] + list(args),
            capture_output=True, text=True, env=env)

    # --- the plan --------------------------------------------------------

    def test_already_present_package_never_appears_in_the_plan(self):
        self.make_tree()
        r = self.run_uninstall()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('python3-gssapi', r.stdout)
        self.assertNotIn('krb5-user', r.stdout)

    def test_dry_run_is_the_default_and_touches_nothing(self):
        self.make_tree()
        r = self.run_uninstall()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('DRY RUN', r.stdout)
        for rel in ('opt/mcp-krb/mcp-krb-bridge.py', 'etc/krb5.conf',
                    'etc/claude-code/managed-mcp.json',
                    'usr/local/share/ca-certificates/realm-ca.crt'):
            self.assertTrue(os.path.exists(self.path(rel)), rel + ' was touched')
        with open(self.path('etc/krb5.conf')) as f:
            self.assertEqual(f.read(), 'THE KIT VERSION')

    def test_keep_packages_drops_them_from_the_plan(self):
        self.make_tree()
        r = self.run_uninstall('--keep-packages')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('remove package', r.stdout)

    # --- refusals --------------------------------------------------------

    def test_missing_manifest_exits_nonzero_and_removes_nothing(self):
        self.make_tree(manifest=None)
        r = self.run_uninstall('--yes')
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(os.path.exists(self.path('opt/mcp-krb/mcp-krb-bridge.py')))
        self.assertTrue(os.path.exists(self.path('etc/claude-code/managed-mcp.json')))

    def test_malformed_manifest_exits_nonzero_and_removes_nothing(self):
        self.make_tree(manifest=None)
        self.put('opt/mcp-krb/install-manifest.json', '{this is not json')
        r = self.run_uninstall('--yes')
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(os.path.exists(self.path('opt/mcp-krb/mcp-krb-bridge.py')))

    def test_unknown_manifest_version_is_refused(self):
        bad = dict(MANIFEST, manifest_version=99)
        self.make_tree(manifest=bad)
        r = self.run_uninstall('--yes')
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(os.path.exists(self.path('opt/mcp-krb/mcp-krb-bridge.py')))

    def test_paths_outside_the_kit_are_never_removed(self):
        evil = dict(MANIFEST)
        evil['created'] = MANIFEST['created'] + ['/etc/passwd']
        self.make_tree(manifest=evil)
        self.put('etc/passwd', 'root:x:0:0')
        r = self.run_uninstall('--yes', '--managed')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(self.path('etc/passwd')))
        self.assertIn('not a path this kit owns', r.stdout)

    # --- applying --------------------------------------------------------

    def test_yes_removes_created_and_restores_replaced(self):
        self.make_tree()
        r = self.run_uninstall('--yes', '--managed')
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertFalse(os.path.exists(self.path('opt/mcp-krb')))
        self.assertFalse(os.path.exists(self.path('etc/claude-code/managed-mcp.json')))
        self.assertFalse(os.path.exists(
            self.path('usr/local/share/ca-certificates/realm-ca.crt')))
        # replaced means restored, not deleted
        with open(self.path('etc/krb5.conf')) as f:
            self.assertEqual(f.read(), 'THE PRISTINE ORIGINAL')

    def test_without_managed_the_machine_wide_registration_stays(self):
        self.make_tree()
        r = self.run_uninstall('--yes')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(self.path('etc/claude-code/managed-mcp.json')))
        self.assertIn('--managed', r.stdout)

    # --- the enrolment invariant ----------------------------------------

    def test_no_code_path_ever_calls_ipa_client_install(self):
        # Static: every mention of the command in the script must be prose
        # (a comment or a printed line), never an execution.
        with open(os.path.join(REPO, 'client', 'uninstall.sh')) as f:
            for n, line in enumerate(f, 1):
                if 'ipa-client-install' not in line:
                    continue
                s = line.strip()
                self.assertTrue(
                    s.startswith('#') or s.startswith('echo') or
                    s.startswith('printf') or s.startswith('say'),
                    'uninstall.sh:%d looks like it executes ipa-client-install: %r'
                    % (n, line))

    def test_ipa_client_install_is_not_executed_even_with_yes(self):
        # Runtime, belt and braces on the static check: a trap executable
        # earlier on PATH records any invocation.
        self.make_tree()
        stub_dir = os.path.join(self.root, 'stub-bin')
        os.makedirs(stub_dir)
        log = os.path.join(self.root, 'stub.log').replace(os.sep, '/')
        stub = os.path.join(stub_dir, 'ipa-client-install')
        with open(stub, 'w') as f:
            f.write('#!/bin/sh\necho called >> %s\n' % log)
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IEXEC)
        r = self.run_uninstall('--yes', '--managed', path_prefix=stub_dir)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.root, 'stub.log')))
        # and the separate operation is still named for the operator
        self.assertIn('ipa-client-install --uninstall', r.stdout)


if __name__ == '__main__':
    unittest.main()
