"""The three places that must agree about config.js.

app.js reads keys off window.SITE, run.sh's write_config emits them, and
config.example.js documents them for anyone hand-writing the file. Nothing ties
those together, so a key added to two of the three is silently broken: the page
falls back to a placeholder and the deployment looks fine until someone reads the
rendered command and finds <set domain in config.js> in it.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP_JS = ROOT / "client" / "web" / "app.js"
CONFIG_EXAMPLE = ROOT / "client" / "web" / "config.example.js"
RUN_SH = ROOT / "server" / "install" / "run.sh"


def keys_app_js_reads():
    """SITE.<key> occurrences in app.js."""
    return set(re.findall(r"\bSITE\.([A-Za-z_][A-Za-z0-9_]*)", APP_JS.read_text(encoding="utf-8")))


def keys_run_sh_emits():
    """Keys printed into config.js by write_config."""
    text = RUN_SH.read_text(encoding="utf-8")
    start = text.index("write_config()")
    body = text[start:text.index('} > "$1/config.js"', start)]
    return set(re.findall(r'printf\s+"\s*([A-Za-z_][A-Za-z0-9_]*):', body))


def keys_config_example_documents():
    text = CONFIG_EXAMPLE.read_text(encoding="utf-8")
    body = text[text.index("window.SITE"):]
    return set(re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:", body, re.M))


class TestClientConfigKeys(unittest.TestCase):

    def test_every_key_app_js_reads_is_emitted_by_the_installer(self):
        missing = keys_app_js_reads() - keys_run_sh_emits()
        self.assertEqual(missing, set(),
                         "app.js reads these but run.sh never writes them: %s" % sorted(missing))

    def test_every_emitted_key_is_documented_in_the_example(self):
        missing = keys_run_sh_emits() - keys_config_example_documents()
        self.assertEqual(missing, set(),
                         "run.sh emits these but config.example.js does not document them: %s"
                         % sorted(missing))

    def test_example_documents_nothing_the_installer_will_not_write(self):
        extra = keys_config_example_documents() - keys_run_sh_emits()
        self.assertEqual(extra, set(),
                         "config.example.js documents keys run.sh never emits: %s" % sorted(extra))

    def test_download_base_is_wired_end_to_end(self):
        # The reason this file exists: a host that serves the page and the files
        # from different paths has no other way to say so, and the fallback is
        # hand-editing the served page, which forks it from the repo for good.
        self.assertIn("downloadBase", keys_app_js_reads())
        self.assertIn("downloadBase", keys_run_sh_emits())
        self.assertIn("downloadBase", keys_config_example_documents())
        self.assertIn("CLIENT_DOWNLOAD_BASE", RUN_SH.read_text(encoding="utf-8"))

    def test_download_base_defaults_to_the_pages_own_directory(self):
        # Blank must keep the old behaviour, or every existing deployment breaks
        # on upgrade.
        app = APP_JS.read_text(encoding="utf-8")
        self.assertIn("location.pathname.replace", app)
        self.assertRegex(app, r"if\s*\(\s*SITE\.downloadBase\s*\)")


if __name__ == "__main__":
    unittest.main()
