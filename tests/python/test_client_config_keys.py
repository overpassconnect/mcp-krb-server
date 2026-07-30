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

    def test_ca_toggle_is_wired_through_every_layer(self):
        page = (ROOT / "client" / "web" / "index.html").read_text(encoding="utf-8")
        app = APP_JS.read_text(encoding="utf-8")
        for marker in ("__CA_BEGIN__", "__CA_END__", "__CA_ARG__"):
            self.assertIn(marker, page, "%s missing from the page" % marker)
        self.assertIn("__CA_ARG__", app, "app.js does not substitute __CA_ARG__")
        self.assertIn("__CA_BEGIN__", app, "app.js does not handle the stanza markers")
        self.assertIn("caInstall", keys_app_js_reads())
        self.assertIn("caInstall", keys_run_sh_emits())
        self.assertIn("CLIENT_CA_INSTALL", RUN_SH.read_text(encoding="utf-8"))

    def test_ca_markers_never_survive_into_a_rendered_block(self):
        # Whichever way the toggle goes, the markers themselves must be gone:
        # a leftover __CA_BEGIN__ would be pasted into a shell as a command.
        app = APP_JS.read_text(encoding="utf-8")
        self.assertRegex(app, r"__CA_\(\?:BEGIN\|END\)__",
                         "app.js must strip the markers when the CA step is kept")
        self.assertRegex(app, r"__CA_BEGIN__[\s\S]{0,80}__CA_END__",
                         "app.js must drop the whole stanza when the CA step is off")

    def test_skip_ca_exists_for_the_toggle_to_target(self):
        # __CA_ARG__ resolves to --skip-ca; the script has to accept it, or the
        # page emits a command that dies on an unknown argument.
        macos = (ROOT / "client" / "setup-macos.sh").read_text(encoding="utf-8")
        self.assertIn("--skip-ca)", macos)
        self.assertIn("'--skip-ca'", APP_JS.read_text(encoding="utf-8"))

    def test_download_base_defaults_to_the_pages_own_directory(self):
        # Blank must keep the old behaviour, or every existing deployment breaks
        # on upgrade.
        app = APP_JS.read_text(encoding="utf-8")
        self.assertIn("location.pathname.replace", app)
        self.assertRegex(app, r"if\s*\(\s*SITE\.downloadBase\s*\)")


if __name__ == "__main__":
    unittest.main()
