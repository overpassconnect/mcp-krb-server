#!/bin/sh
# Run all unit tests. Hermetic: a fake gssapi stands in for python3-gssapi, so
# the suite runs anywhere with python3 (Windows, Linux, CI) - no KDC, no native
# packages, and no MCP SDK. For the live Kerberos integration checks see
# ../SECURITY.md, section "The test suite" (they need a real FreeIPA-enrolled host).
#
# test_tool_policy_invariant.py enforces SECURITY.md checklist item 12 (every
# @mcp.tool calls require() with its own name and has a TOOL_GROUPS entry). It
# parses mcp_server.py rather than importing it, so it cannot skip on a host
# without the SDK; a skipped invariant check is an unenforced one.
set -e
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

echo "=================== unit tests (python -m unittest) ==================="
( cd "$here/python" && python3 -m unittest -v )

echo ""
echo "ALL UNIT TESTS PASSED"
