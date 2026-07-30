"""Broken line continuations in the shipped shell scripts.

`sh -n` does not catch these. A stray `\\n` where a backslash-newline was meant
is valid syntax: the shell unescapes it to a literal `n` and tries to run a
command by that name. It only fails at runtime, on the line that contains it.

That is how one shipped: every check run against setup-macos.sh was a --dry-run,
and the broken line sat in the one block a dry run skips. A syntax check plus a
dry run can both pass while the real path is broken, so this looks at the text.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHELL = sorted(
    list((ROOT / "client").glob("*.sh"))
    + list((ROOT / "server" / "install").glob("*.sh"))
    + list((ROOT / "tests").glob("*.sh"))
)

# A backslash-n with whitespace in front is a continuation someone flattened.
# Real uses are inside a quoted format string (printf 'x\n') with no space, or
# a regex in an embedded script, which this does not resemble.
BROKEN_CONTINUATION = re.compile(r"[ \t]\\n(?:[ \t]|$)")


class TestShellContinuations(unittest.TestCase):

    def test_shell_files_were_found(self):
        # A glob that silently matches nothing would make every test below pass.
        self.assertGreater(len(SHELL), 3, "expected several shell scripts, found %s" % SHELL)

    def test_no_flattened_line_continuations(self):
        bad = []
        for path in SHELL:
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if BROKEN_CONTINUATION.search(line):
                    bad.append("%s:%d: %s" % (path.relative_to(ROOT), n, line.strip()[:90]))
        self.assertEqual(bad, [], "literal \\n where a line continuation was meant:\n" + "\n".join(bad))

    def test_no_crlf(self):
        # Same family: authored on Windows, executed on Linux and macOS, where a
        # trailing CR turns `set -eu` into an unknown option.
        bad = [str(p.relative_to(ROOT)) for p in SHELL if b"\r\n" in p.read_bytes()]
        self.assertEqual(bad, [], "CRLF line endings in shell scripts: %s" % bad)

    def test_every_script_starts_with_a_shebang(self):
        missing = [str(p.relative_to(ROOT)) for p in SHELL
                   if not p.read_text(encoding="utf-8").startswith("#!")]
        self.assertEqual(missing, [], "no shebang: %s" % missing)


if __name__ == "__main__":
    unittest.main()
