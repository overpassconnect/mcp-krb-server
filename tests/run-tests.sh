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
echo "=================== powershell tests (Pester) ========================="
# The Windows half of the client kit is PowerShell, and JsoncEdit.ps1 rewrites
# the user's settings.json by hand; its tests target Windows PowerShell 5.1,
# the runtime those scripts actually execute under, and spawn `powershell` as a
# child process. So they run only where Windows PowerShell exists - pwsh on a
# Linux box is deliberately not enough. Skipping is announced, never silent,
# and CI runs these on windows-latest, so a local skip cannot quietly become
# the only outcome.
PWSH=""
if command -v powershell >/dev/null 2>&1; then PWSH="powershell"; fi
if [ -z "$PWSH" ]; then
    echo "SKIPPED: no Windows PowerShell on PATH; the Pester tests run in CI on windows-latest."
else
    # Git Bash hands PowerShell a /c/... path it cannot open; cygpath fixes it
    # where it exists (Windows) and is absent where the path is already fine.
    psdir="$here/powershell"
    if command -v cygpath >/dev/null 2>&1; then psdir="$(cygpath -w "$psdir")"; fi
    "$PWSH" -NoProfile -ExecutionPolicy Bypass -Command "
        \$m = Get-Module -ListAvailable Pester | Where-Object { \$_.Version.Major -ge 5 }
        if (-not \$m) {
            Write-Host 'SKIPPED: Pester 5+ not installed (Install-Module Pester -Force -SkipPublisherCheck); CI runs these on windows-latest.'
            exit 0
        }
        \$r = Invoke-Pester -Path '$psdir' -PassThru -Output Detailed
        # TotalCount 0 would mean the test files were not even found, which
        # must fail rather than read as a pass.
        if (\$r.FailedCount -gt 0 -or \$r.TotalCount -eq 0) { exit 1 }
        exit 0
    " || { echo "POWERSHELL TESTS FAILED"; exit 1; }
fi

echo ""
echo "ALL UNIT TESTS PASSED"
