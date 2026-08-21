"""Every interactive placeholder must be reachable by an input that fills it.

The page offers a small form per OS: type your username once and the commands
below rewrite themselves. That works by <div class="fill" data-fill="ID">
driving <code id="ID">.

The failure this guards is silent and looks like success. When the macOS tab was
split into separate paste blocks so the paste would stop at the sudo prompt, the
kinit line moved into a block no fill group pointed at. Typing a username still
visibly updated the install command above, so the form looked fine, while the
kinit below kept saying <your-ipa-username>. Someone pastes that and gets
'Cannot find KDC for realm' for a principal that does not exist.

So the rule is not "the form works" but "no placeholder is left behind": every
token an input claims to fill must be reachable in some block that input drives.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = (ROOT / "client" / "web" / "index.html").read_text(encoding="utf-8")
APP = (ROOT / "client" / "web" / "app.js").read_text(encoding="utf-8")

CODE = dict(re.findall(r'<pre><code id="([^"]+)">(.*?)</code></pre>', PAGE, re.S))


def fill_groups():
    """(ids driven, tokens offered) for each fill form on the page."""
    out = []
    for m in re.finditer(r'<div class="fill" data-fill="([^"]+)">(.*?)</div>', PAGE, re.S):
        ids = [i for i in m.group(1).split() if i]
        tokens = re.findall(r'data-token="([^"]+)"', m.group(2))
        out.append((ids, tokens))
    return out


class EveryPlaceholderHasAnInput(unittest.TestCase):

    def test_the_page_has_fill_groups_and_blocks(self):
        self.assertGreaterEqual(len(fill_groups()), 3)
        self.assertIn("mac-script", CODE)
        self.assertIn("mac-kinit", CODE)

    def test_every_group_targets_blocks_that_exist(self):
        missing = [i for ids, _ in fill_groups() for i in ids if i not in CODE]
        self.assertEqual([], missing,
                         "data-fill names code blocks that do not exist: %s" % missing)

    def test_no_placeholder_is_left_unfillable(self):
        """Any token offered by a form must not survive in a block that form
        does not drive, within the same OS section."""
        orphans = []
        for m in re.finditer(r'<section id="([^"]+)"(.*?)</section>', PAGE, re.S):
            sid, body = m.group(1), m.group(2)
            tokens = set(re.findall(r'data-token="([^"]+)"', body))
            if not tokens:
                continue
            driven = set()
            for dm in re.finditer(r'data-fill="([^"]+)"', body):
                driven.update(i for i in dm.group(1).split() if i)
            for bid, code in re.findall(r'<pre><code id="([^"]+)">(.*?)</code></pre>', body, re.S):
                if bid in driven:
                    continue
                for tok in tokens:
                    if tok in code:
                        orphans.append("%s: block %r still contains %s with no input driving it"
                                       % (sid, bid, tok))
        self.assertEqual([], orphans,
                         "placeholders nobody can fill: %s" % orphans)

    def test_app_js_supports_a_list_of_ids(self):
        self.assertRegex(APP, r"data-fill'\)\.split\(",
                         "app.js must split data-fill, or a multi-block group "
                         "silently fills only the first")


if __name__ == "__main__":
    unittest.main()
