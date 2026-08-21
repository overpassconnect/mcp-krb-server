"""No copy-paste block may continue past a command that authenticates.

Pasting several lines into a terminal puts them all in one input queue, and an
authentication prompt reads from that same queue. So a `sudo` in the middle of a
block eats the next pasted line as the password and silently discards every line
after it.

This is not theoretical. The macOS block had `sudo security add-trusted-cert` in
the middle, followed by the download and the install. Pasting it ran the CA step,
swallowed `cd "$(mktemp -d)"` as a password attempt, and dropped the rest. The
user saw an authentication prompt and then nothing: no file, no error, and a
temp directory they could not find again. Nothing in the page or the scripts
could have reported it, because the lines never reached a shell.

macOS makes it worse than a password prompt: sudo may use Touch ID, and touching
the System keychain raises its own authorisation dialog, so pre-caching
credentials does not save you. The only robust rule is that the paste ENDS at
the prompt.

Linux was always fine by accident rather than design: its elevation happens to
be the last command in each block. This test makes that a rule rather than luck.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = (ROOT / "client" / "web" / "index.html").read_text(encoding="utf-8")

# Commands that can raise a password, biometric or keychain prompt.
PROMPTS = re.compile(r"\b(sudo|security add-trusted-cert)\b")


def blocks():
    """Each <pre><code id=...> as (id, [logical commands])."""
    out = []
    for m in re.finditer(r'<pre><code id="([^"]+)">(.*?)</code></pre>', PAGE, re.S):
        cmds, cur = [], ""
        for raw in m.group(2).split("\n"):
            line = raw.rstrip()
            if not line.strip() or line.strip().startswith("__CA_"):
                continue
            cur = (cur + " " + line.strip()) if cur else line.strip()
            if line.endswith(chr(92)) or line.endswith("`"):   # sh and PowerShell continuations
                cur = cur.rstrip(chr(92) + "`").rstrip()
                continue
            cmds.append(cur)
            cur = ""
        if cur:
            cmds.append(cur)
        out.append((m.group(1), cmds))
    return out


class NothingFollowsAPrompt(unittest.TestCase):

    def test_the_page_has_blocks_this_test_can_see(self):
        ids = [b[0] for b in blocks()]
        self.assertIn("mac-ca", ids)
        self.assertIn("linux-cmd", ids)
        self.assertGreaterEqual(len(ids), 8)

    def test_no_command_follows_an_authenticating_one(self):
        bad = []
        for bid, cmds in blocks():
            for i, c in enumerate(cmds[:-1]):
                if not PROMPTS.search(c):
                    continue
                rest = cmds[i + 1:]
                # Alternatives of the SAME command (a dry run then --yes) are a
                # menu to choose from, not a sequence to run, so they are fine.
                head = c.split("#")[0].strip().split()[:3]
                if all(r.split("#")[0].strip().split()[:3] == head for r in rest):
                    continue
                bad.append("%s: %r then %r" % (bid, c[:60], rest[0][:60]))
        self.assertEqual([], bad,
                         "these blocks continue past an authentication prompt, so the "
                         "next pasted line is consumed as the password and the rest is "
                         "lost: %s" % bad)

    def test_the_macos_ca_step_is_its_own_block(self):
        ids = [b[0] for b in blocks()]
        self.assertIn("mac-ca", ids, "the CA stanza must be a separate paste block")
        self.assertIn("mac-script", ids, "the install must be a separate paste block")
        ca = dict(blocks())["mac-ca"]
        self.assertTrue(any(PROMPTS.search(c) for c in ca))
        self.assertTrue(PROMPTS.search(ca[-1]),
                        "the CA block must END on the authenticating command")


if __name__ == "__main__":
    unittest.main()
