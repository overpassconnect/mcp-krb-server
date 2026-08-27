# uninstall.ps1 - reverse what setup.ps1 recorded in the install manifest.
#
#   .\uninstall.ps1          # default: DRY RUN - print the plan, change nothing
#   .\uninstall.ps1 -Yes     # apply the plan
#
# Everything removed or restored here is justified by an entry in
# %USERPROFILE%\bin\mcp-krb-manifest.json saying setup.ps1 created or changed
# it. The VS Code keys are the reason this script exists at all: the old
# documented rollback deleted ssh-dispatch.bat and said nothing about
# remote.SSH.path, which left Remote-SSH launching a file that no longer
# existed, for every host, including ones that worked before the kit arrived.
#
# What this script deliberately does not do:
#   - `wsl --unregister`. Deleting an entire Linux filesystem is not an
#     uninstall step for an SSH shim; the command is printed for whoever
#     genuinely wants it. A test asserts no code path here runs it.
#   - delete .bak files. settings.json.bak and .claude.json.bak may predate
#     this kit, so they are reported by path and left where they are.
#   - touch the default WSL distro. The WSL cleanup runs uninstall.sh inside
#     the distro the manifest names, with -d, because on a multi-distro
#     machine "the default" is frequently docker-desktop or some other distro
#     the installer never touched.
param(
    [switch]$Yes,
    [switch]$DryRun,
    # Test hooks. Each defaults to the real location; the Pester suite points
    # them at a synthetic tree so the whole script is exercised for real
    # without touching the machine it runs on.
    [string]$ManifestPath = '',
    [string]$UserProfile = $env:USERPROFILE,
    [string]$ProfilePath = '',
    [string]$WslCommand = 'wsl.exe'
)
$ErrorActionPreference = 'Stop'
function Say($m) { Write-Host "[uninstall] $m" }
function Warn($m) { Write-Host "[warn ] $m" -ForegroundColor Yellow }

$binDir = Join-Path $UserProfile 'bin'
if (-not $ManifestPath) { $ManifestPath = Join-Path $binDir 'mcp-krb-manifest.json' }
if (-not $ProfilePath) {
    # The same reconstruction setup.ps1 uses, for the same reason: $PROFILE is
    # empty in the runspaces fleet tooling uses.
    $ProfilePath = $PROFILE.CurrentUserAllHosts
    if ([string]::IsNullOrWhiteSpace($ProfilePath)) {
        $docs = [Environment]::GetFolderPath('MyDocuments')
        if ([string]::IsNullOrWhiteSpace($docs)) { $docs = Join-Path $UserProfile 'Documents' }
        $dir = if ($PSVersionTable.PSEdition -eq 'Core') { 'PowerShell' } else { 'WindowsPowerShell' }
        $ProfilePath = Join-Path (Join-Path $docs $dir) 'profile.ps1'
    }
}

$act = [bool]$Yes -and -not $DryRun
if ($act) { Say "uninstalling per $ManifestPath" }
else { Say "DRY RUN - the plan per $ManifestPath (pass -Yes to apply)" }

if (-not (Test-Path $ManifestPath)) {
    Say "ERROR: no install manifest at $ManifestPath - refusing to guess."
    Say ''
    Say 'The manifest is what records which of the following setup.ps1 actually'
    Say 'created on THIS machine, as opposed to what was already here:'
    Say "  $binDir\ssh-dispatch.bat, and $binDir itself"
    Say '  the wslssh and mcp-fetch lines in the PowerShell profile (marker: setup.ps1)'
    Say '  remote.SSH.* keys in each editor settings.json, and their prior values'
    Say '  the internal-tools entry in .claude.json'
    Say '  everything inside the WSL distro (its own manifest lives there)'
    Say ''
    Say 'Without it, removal cannot be told apart from vandalising values you set'
    Say 'yourself. Reverse the pieces you know are the kit''s by hand instead.'
    exit 1
}
try { $doc = [IO.File]::ReadAllText($ManifestPath) | ConvertFrom-Json }
catch { Say "ERROR: $ManifestPath does not parse - nothing was removed."; exit 1 }
if ($doc.manifest_version -ne 1) {
    Say "ERROR: unknown manifest_version '$($doc.manifest_version)' - nothing was removed."
    exit 1
}

$created = @();     if ($doc.PSObject.Properties.Name -contains 'created')      { $created = @($doc.created) }
$createdDirs = @(); if ($doc.PSObject.Properties.Name -contains 'created_dirs') { $createdDirs = @($doc.created_dirs) }

# The manifest is data, not authority: only paths under this user's profile
# (or the explicitly resolved PowerShell profile) may be acted on, so a
# corrupted manifest cannot direct the run at an arbitrary file.
function Test-Ours([string]$Path) {
    try { $p = [IO.Path]::GetFullPath($Path) } catch { return $false }
    $u = [IO.Path]::GetFullPath($UserProfile)
    $prof = [IO.Path]::GetFullPath($ProfilePath)
    return $p.StartsWith($u, [StringComparison]::OrdinalIgnoreCase) -or
           $p -eq $prof
}

# --- 1. files the manifest says setup.ps1 created ---------------------------
# The profile is handled separately below (only the marker line is the kit's),
# and the manifest itself goes last, after everything it justifies.
foreach ($f in $created) {
    if ($f -ieq $ManifestPath -or $f -ieq $ProfilePath) { continue }
    if (-not (Test-Ours $f)) {
        Say "  left alone: $f (manifest names it, but it is not under $UserProfile)"
        continue
    }
    if (Test-Path $f) {
        Say "  remove $f (created by installer)"
        if ($act) { Remove-Item -Force $f }
    }
}

# --- 2. the profile lines, by marker comment, never by function name --------
# A user who wrote their own `function wslssh` before or after the kit did
# keeps it: only the lines setup.ps1 stamped with its markers are the kit's.
# One marker per function it writes; a function added to setup.ps1 without its
# marker added here survives uninstall forever.
# That is not hypothetical: the git marker was missing here from the day wslgit
# was added, so every uninstall left it behind. test_profile_marker_parity.py
# now fails if setup.ps1 stamps a marker this list does not carry.
$markers = @(
    '# Kerberos ssh via WSL (setup.ps1)',
    '# Kerberos fetch via WSL (setup.ps1)',
    '# Kerberos git via WSL (setup.ps1)',
    '# Kerberos kinit via WSL (setup.ps1)',
    '# Kerberos klist via WSL (setup.ps1)',
    '# Kerberos kdestroy via WSL (setup.ps1)'
)
if (Test-Path $ProfilePath) {
    $lines = @(Get-Content -Path $ProfilePath)
    $kept = @($lines | Where-Object {
        $line = $_.TrimEnd()
        -not (@($markers | Where-Object { $line.EndsWith($_) }).Count)
    })
    if ($kept.Count -ne $lines.Count) {
        Say "  remove $($lines.Count - $kept.Count) kit line(s) from $ProfilePath (matched by marker comment)"
        if ($act) {
            $remaining = @($kept | Where-Object { $_.Trim() })
            if ($remaining.Count -eq 0 -and ($created | Where-Object { $_ -ieq $ProfilePath })) {
                # The kit created this file and nothing of the user's is in it.
                Say "  remove $ProfilePath (created by installer, now empty)"
                Remove-Item -Force $ProfilePath
            } else {
                [IO.File]::WriteAllLines($ProfilePath, [string[]]$kept)
            }
        }
    }
}

# --- 3. settings keys back to their prior values ----------------------------
# null prior means the key was absent before the kit set it, so it is removed;
# a string is the user's own raw JSON scalar, restored verbatim. Both go
# through JsoncEdit so the user's comments and formatting survive, the same
# way they survived the install.
$helper = Join-Path $PSScriptRoot 'JsoncEdit.ps1'
$haveHelper = Test-Path $helper
if ($haveHelper) { . $helper }
$priorFiles = @()
if ($doc.PSObject.Properties.Name -contains 'prior_values') {
    $priorFiles = @($doc.prior_values.PSObject.Properties)
}
foreach ($fileProp in $priorFiles) {
    $sPath = $fileProp.Name
    if (-not (Test-Ours $sPath)) {
        Say "  left alone: $sPath (manifest names it, but it is not under $UserProfile)"
        continue
    }
    if (-not (Test-Path $sPath)) { continue }
    if (-not $haveHelper) {
        Warn "JsoncEdit.ps1 is not beside this script - settings keys in $sPath were left as installed."
        continue
    }
    $orig = [IO.File]::ReadAllText($sPath)
    if (-not (Test-JsoncValid $orig)) {
        Warn "${sPath}: not valid JSON/JSONC - left alone."
        continue
    }
    $text = $orig
    $ok = $true
    foreach ($kv in @($fileProp.Value.PSObject.Properties)) {
        $key = $kv.Name
        $prior = $kv.Value
        if ($null -eq $prior) {
            Say "  remove $key from $sPath (absent before install)"
            $new = Remove-JsoncKey -Text $text -Key $key
        } else {
            Say "  restore $key = $prior in $sPath (the user's own value)"
            $new = Set-JsoncKey -Text $text -Key $key -JsonValue ([string]$prior)
        }
        if ($null -eq $new) {
            Warn "${sPath}: $key has a shape this script will not edit blindly - left alone."
            $ok = $false; break
        }
        $text = $new
    }
    if ($ok -and $text -ne $orig) {
        if (-not (Test-JsoncValid $text)) {
            Warn "${sPath}: edit would produce invalid JSON - aborted, file untouched."
        } elseif ($act) {
            [IO.File]::WriteAllText($sPath, $text, (New-Object Text.UTF8Encoding($false)))
            Say "  ${sPath}: restored (comments preserved)"
        }
    }
}

# --- 4. the Claude Code registration ----------------------------------------
# Edited directly, the way the fallback in setup.ps1 wrote it: `claude mcp
# remove` is unavailable on exactly the machines that needed the fallback
# registration in the first place (desktop app, no CLI), so it cannot be the
# only route. Same conservatism as the installer: round-trip the whole
# document, re-parse before replacing, copy aside first.
$reg = ''
if ($doc.PSObject.Properties.Name -contains 'claude_registration') { $reg = [string]$doc.claude_registration }
$cfg = Join-Path $UserProfile '.claude.json'
if ($reg -and (Test-Path $cfg)) {
    $cdoc = $null
    try { $cdoc = [IO.File]::ReadAllText($cfg) | ConvertFrom-Json }
    catch { Warn "$cfg is not valid JSON - left untouched." }
    if ($cdoc -and $cdoc.PSObject.Properties.Name -contains 'mcpServers' -and
        $cdoc.mcpServers.PSObject.Properties.Name -contains $reg) {
        Say "  remove mcpServers.$reg from $cfg (registered by installer)"
        if ($act) {
            $cdoc.mcpServers.PSObject.Properties.Remove($reg)
            $out = $cdoc | ConvertTo-Json -Depth 100
            $parses = $true
            try { $null = $out | ConvertFrom-Json } catch { $parses = $false }
            if (-not $parses) {
                Warn 'the rewritten .claude.json would not parse - nothing written.'
            } else {
                Copy-Item $cfg "$cfg.bak" -Force -ErrorAction SilentlyContinue
                [IO.File]::WriteAllText($cfg, $out, (New-Object Text.UTF8Encoding($false)))
            }
        }
    }
} elseif (-not $reg) {
    Say '  MCP registration: none recorded as the installer''s - left alone.'
}

# --- 5. the WSL side, in the distro the installer provisioned ---------------
# Never the default distro: on a multi-distro machine the default is often one
# the installer never touched, which is exactly the bug the old rollback
# command had. uninstall.sh runs inside the recorded distro and reverses the
# manifest that lives there.
$distro = ''
if ($doc.PSObject.Properties.Name -contains 'wsl_distro') { $distro = [string]$doc.wsl_distro }
$wslScript = Join-Path $PSScriptRoot 'uninstall.sh'
if ($distro) {
    Say "  WSL ($distro): run uninstall.sh inside the distro the installer provisioned"
    if (-not (Test-Path $wslScript)) {
        Warn "uninstall.sh is not beside this script - fetch it and run it yourself:"
        Warn "  wsl -d $distro -u root -e sh /path/to/uninstall.sh --yes"
    } else {
        $tmp = Join-Path $env:TEMP ("wsl-uninstall-" + [guid]::NewGuid().ToString('N') + '.sh')
        try {
            $body = [IO.File]::ReadAllText($wslScript) -replace "`r`n", "`n"
            [IO.File]::WriteAllText($tmp, $body)
            $wslPath = '/mnt/' + $tmp.Substring(0, 1).ToLower() + ($tmp.Substring(2) -replace '\\', '/')
            $mode = if ($act) { '--yes' } else { '--dry-run' }
            # The reverse-bridge anchor is a per-user WSL service; tear it down as
            # the user (default, not root) before the root uninstall removes the
            # kit tree it lives in. --uninstall queries nothing, so no ticket is
            # needed. Dry runs skip it, matching everything else here.
            if ($act) {
                & $WslCommand -d $distro -e sh -c '[ -x /opt/mcp-krb/install-anchor.sh ] && /opt/mcp-krb/install-anchor.sh --uninstall' 2>$null
            }
            & $WslCommand -d $distro -u root -e sh $wslPath $mode
            if ($LASTEXITCODE -ne 0) {
                Warn "WSL uninstall reported exit code $LASTEXITCODE - review its output above."
            }
            # The managed ~/.ssh/config block is sentinel-delimited and edited
            # as the login user, not root, because it is the user's file.
            Say "  WSL ($distro): remove the setup-workstation block from ~/.ssh/config"
            if ($act) {
                & $WslCommand -d $distro -e sh -c "[ -f ~/.ssh/config ] && sed -i '/# BEGIN setup-workstation/,/# END setup-workstation/d' ~/.ssh/config || true"
                if ($LASTEXITCODE -ne 0) { Warn 'could not edit ~/.ssh/config inside WSL.' }
            }
        } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
    }
    Say "  the WSL distro itself stays registered: deleting an entire Linux"
    Say "  filesystem is not an uninstall step for an SSH shim. If you truly"
    Say "  want it gone, that is:  wsl --unregister $distro"
} else {
    Warn 'the manifest records no WSL distro, so WSL was not touched. If setup.ps1'
    Warn 'provisioned one, run uninstall.sh inside that distro yourself:'
    Warn '  wsl -d <distro> -u root -e sh /path/to/uninstall.sh'
}

# --- 6. report .bak files, never delete them --------------------------------
# settings.json.bak and .claude.json.bak may predate this kit; whether they
# still matter is the user's call.
$baks = @()
foreach ($fileProp in $priorFiles) {
    if (Test-Path ($fileProp.Name + '.bak')) { $baks += ($fileProp.Name + '.bak') }
}
if (Test-Path "$cfg.bak") { $baks += "$cfg.bak" }
if ($baks.Count -gt 0) {
    Say '  left in place (backups, possibly older than this kit - review yourself):'
    foreach ($b in $baks) { Say "    $b" }
}

# --- 7. the manifest itself, then the bin dir if the kit created it ---------
Say "  remove $ManifestPath (it no longer describes this machine)"
if ($act) {
    Remove-Item -Force $ManifestPath
    if (($createdDirs | Where-Object { $_ -ieq $binDir }) -and (Test-Path $binDir) -and
        @(Get-ChildItem -Force $binDir).Count -eq 0) {
        Say "  remove $binDir (created by installer, now empty)"
        Remove-Item -Force $binDir
    }
}

Say ''
if ($act) {
    Say 'Done. Windows was never enrolled in the realm, so there is nothing'
    Say 'realm-side to undo for this machine.'
} else {
    Say 'Dry run: nothing was changed. Re-run with -Yes to apply.'
}
