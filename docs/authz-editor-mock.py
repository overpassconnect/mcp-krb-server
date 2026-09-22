#!/usr/bin/env python3
"""Regenerate the README's picture of the policy editor.

The page is built from the real template in server/authz_editor.py, so the
picture cannot drift from the product: only load() is replaced by a canned
document with example tools, example groups and an example realm. Nothing in it
comes from a deployment.

    python3 docs/authz-editor-mock.py light > /tmp/editor-light.html
    python3 docs/authz-editor-mock.py dark  > /tmp/editor-dark.html
    chrome --headless=new --hide-scrollbars --force-device-scale-factor=2 \
           --window-size=1280,900 --screenshot=docs/authz-editor.png /tmp/editor-light.html
    chrome --headless=new --hide-scrollbars --force-device-scale-factor=2 \
           --window-size=1280,900 --screenshot=docs/authz-editor-dark.png /tmp/editor-dark.html

Any Chromium (Chrome, Edge) renders it; the two files are the same page with the
dark-mode rule removed or forced, so the result does not depend on the theme of
the machine that renders it.
"""
import hashlib
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main():
    theme = sys.argv[1] if len(sys.argv) > 1 else "light"
    src = io.open(os.path.join(ROOT, "server", "authz_editor.py"), encoding="utf-8").read()
    html = re.search(r'_HTML = r"""(.*?)"""\n', src, re.S).group(1)
    authz = io.open(os.path.join(ROOT, "server", "authz.py"), encoding="utf-8").read()
    any_token = re.search(r"ANY_TOKEN\s*=\s*['\"]([^'\"]+)['\"]", authz).group(1)

    policy = {
        "whoami":              {"groups": any_token},
        "list_projects":       {"groups": ["developers", "ops"]},
        "list_docs":           {"groups": ["developers", "ops"]},
        "read_doc":            {"groups": ["developers", "ops"]},
        "list_pull_requests":  {"groups": ["developers"], "forwards_to": "HTTP@git.example.internal"},
        "review_pull_request": {"groups": ["developers"], "forwards_to": "HTTP@git.example.internal"},
        "merge_pull_request":  {"groups": ["senior-developers"], "forwards_to": "HTTP@git.example.internal"},
        "trigger_build":       {"groups": ["developers", "ops"], "forwards_to": "HTTP@ci.example.internal"},
        "build_status":        {"groups": ["developers", "ops"]},
        "restart_service":     {"groups": ["ops"]},
    }
    tools = sorted(list(policy) + ["build_log", "create_repo", "rotate_secret"])
    # The same shape authz.policy_etag() produces: a strong, quoted tag over the
    # canonical policy.
    canon = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    etag = '"' + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:32] + '"'

    doc = json.dumps({"etag": etag, "tools": tools, "policy": policy})
    load = ("function load() {\n"
            "    var d = " + doc + ";\n"
            "    etag = d.etag;\n"
            "    TOOLS = (d.tools || []).slice().sort();\n"
            "    ta.value = JSON.stringify(d.policy, null, 2);\n"
            "    refresh();\n"
            "    show(\"loaded (etag \" + etag + \")\", \"ok\");\n"
            "  }\n")
    html, n = re.subn(r"function load\(\) \{.*?\n  \}\n", lambda _m: load, html, count=1, flags=re.S)
    assert n == 1, "load() not found in the template"
    html = (html.replace("%NONCE%", "mock")
                .replace("%PRINCIPAL%", "alice@EXAMPLE.INTERNAL")
                .replace("%ORIGIN%", "https://mcp.example.internal")
                .replace("%ANYTOKEN%", any_token)
                .replace("%API%", "#"))

    dark_rule = re.search(r"\n  @media \(prefers-color-scheme: dark\) \{.*?\n  \}\n", html, re.S)
    assert dark_rule, "dark-mode rule not found in the template"
    if theme == "dark":
        html = html.replace("@media (prefers-color-scheme: dark)", "@media all")
    else:
        html = html.replace(dark_rule.group(0), "\n")
    # Bytes, so the output is the same file on every platform (text mode on
    # Windows would turn every newline into CRLF).
    sys.stdout.buffer.write(html.encode("utf-8"))


if __name__ == "__main__":
    main()
