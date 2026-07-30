# JsoncEdit.ps1 - minimal, comment-safe editing of VS Code settings.json.
#
# settings.json is JSONC: // and /* */ comments and trailing commas, which
# Windows PowerShell 5.1's ConvertFrom-Json cannot parse. Parse-and-reserialize
# would delete the user's comments and reformat the file, so the text is edited
# surgically.
#
# The core trick: build a mask of the document in which every comment character
# is replaced by a space. Offsets in the mask line up exactly with the real
# text, so the mask is searched (commented-out settings are invisible there)
# and the real text is spliced at the offsets found.
#
# Dot-sourced by setup.ps1; kept separate so it can be unit-tested.

function Get-JsoncMask {
    <#  Returns $Text with all comment characters replaced by spaces.
        String contents are left intact so key/value matching still works. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $chars = $Text.ToCharArray()
    $inStr = $false; $esc = $false; $i = 0
    while ($i -lt $chars.Length) {
        $c = $chars[$i]
        if ($inStr) {
            if ($esc) { $esc = $false }
            elseif ($c -eq '\') { $esc = $true }
            elseif ($c -eq '"') { $inStr = $false }
            $i++; continue
        }
        if ($c -eq '"') { $inStr = $true; $i++; continue }
        if ($c -eq '/' -and ($i + 1) -lt $chars.Length) {
            $n = $chars[$i + 1]
            if ($n -eq '/') {
                while ($i -lt $chars.Length -and $chars[$i] -ne "`n") { $chars[$i] = ' '; $i++ }
                continue
            }
            if ($n -eq '*') {
                while ($i -lt $chars.Length) {
                    $end = ($chars[$i] -eq '*' -and ($i + 1) -lt $chars.Length -and $chars[$i + 1] -eq '/')
                    $chars[$i] = ' '
                    $i++
                    if ($end) { if ($i -lt $chars.Length) { $chars[$i] = ' '; $i++ }; break }
                }
                continue
            }
        }
        $i++
    }
    -join $chars
}

function Test-JsoncValid {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $stripped = Get-JsoncMask $Text
    $stripped = [regex]::Replace($stripped, ',(\s*[}\]])', '$1')   # tolerate trailing commas
    try { $null = $stripped | ConvertFrom-Json; return $true } catch { return $false }
}

function Set-JsoncKey {
    <#  Insert or update a top-level key. Returns the new text, or $null if the
        document shape is not something we are willing to edit blindly. #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$JsonValue
    )
    $mask = Get-JsoncMask $Text
    $esc = [regex]::Escape($Key)

    # 1. Update in place when the key exists with a scalar value. Search the
    #    mask so a commented-out copy of the key is never matched.
    $pattern = '("' + $esc + '"\s*:\s*)("(?:[^"\\]|\\.)*"|true|false|null|-?[\d.]+(?:[eE][-+]?\d+)?)'
    $withValue = [regex]::new($pattern)
    $m = $withValue.Match($mask)
    if ($m.Success) {
        $valStart = $m.Groups[2].Index
        $valLen = $m.Groups[2].Length
        return $Text.Substring(0, $valStart) + $JsonValue + $Text.Substring($valStart + $valLen)
    }

    # 2. The key exists but its value is an object/array (or something else we
    #    do not understand). Inserting would create a duplicate key, which is
    #    silently wrong, so refuse.
    if ([regex]::IsMatch($mask, '"' + $esc + '"\s*:')) { return $null }

    # 3. Insert after the opening brace, which must be the first non-whitespace
    #    character of the mask, so we never inject inside a leading comment.
    $trimmed = $mask.TrimStart()
    if (-not $trimmed.StartsWith('{')) { return $null }
    $idx = $mask.IndexOf('{')
    $rest = $Text.Substring($idx + 1)
    $sep = ','
    if ((Get-JsoncMask $rest).TrimStart().StartsWith('}')) { $sep = '' }   # empty object
    return $Text.Substring(0, $idx + 1) + "`n    `"$Key`": $JsonValue$sep" + $rest
}

function Remove-JsoncKey {
    <#  Remove a top-level key and its scalar value. Returns the new text; the
        text unchanged when the key is absent (a no-op, so uninstall can run
        twice); or $null when the key exists with a value that is not a scalar,
        because guessing where an object or array ends is how a file gets
        corrupted, and the caller should warn and leave it alone instead. #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$Key
    )
    $mask = Get-JsoncMask $Text
    $esc = [regex]::Escape($Key)

    # Depth of an offset in the mask: strings are still present there (only
    # comments are blanked), so they are skipped with the same state machine
    # the mask itself was built with, and braces inside them never count. The
    # key must sit directly in the top-level object (depth 1): Set-JsoncKey
    # inserts at the top level, so a same-named key nested deeper is somebody
    # else's data and must never be the one removed.
    function Get-MaskDepth([string]$MaskText, [int]$Index) {
        $depth = 0; $inStr = $false; $esc2 = $false
        for ($i = 0; $i -lt $Index; $i++) {
            $c = $MaskText[$i]
            if ($inStr) {
                if ($esc2) { $esc2 = $false }
                elseif ($c -eq '\') { $esc2 = $true }
                elseif ($c -eq '"') { $inStr = $false }
                continue
            }
            if ($c -eq '"') { $inStr = $true }
            elseif ($c -eq '{' -or $c -eq '[') { $depth++ }
            elseif ($c -eq '}' -or $c -eq ']') { $depth-- }
        }
        $depth
    }

    # Same scalar shape Set-JsoncKey matches, searched in the mask so a
    # commented-out copy of the key is invisible.
    $pattern = '("' + $esc + '"\s*:\s*)("(?:[^"\\]|\\.)*"|true|false|null|-?[\d.]+(?:[eE][-+]?\d+)?)'
    $m = $null
    foreach ($cand in [regex]::Matches($mask, $pattern)) {
        if ((Get-MaskDepth $mask $cand.Index) -eq 1) { $m = $cand; break }
    }
    if ($null -eq $m) {
        # A top-level key with a non-scalar value: refuse rather than guess.
        foreach ($cand in [regex]::Matches($mask, '"' + $esc + '"\s*:')) {
            if ((Get-MaskDepth $mask $cand.Index) -eq 1) { return $null }
        }
        return $Text   # absent entirely (or only nested/commented): no-op
    }

    $start = $m.Index
    $end = $m.Index + $m.Length   # one past the value

    # The pair leaves with exactly one separating comma. Prefer the trailing
    # one; when the key is last in its object the comma to remove is the
    # leading one. The pair's own line break and indentation go with it, so
    # a set-then-remove round trip does not accrete blank lines.
    $tail = $mask.Substring($end)
    $tm = [regex]::Match($tail, '^\s*,')
    if ($tm.Success) {
        $end += $tm.Length
        while ($start -gt 0 -and ($Text[$start - 1] -eq ' ' -or $Text[$start - 1] -eq "`t")) { $start-- }
        if ($start -gt 0 -and $Text[$start - 1] -eq "`n") {
            $start--
            if ($start -gt 0 -and $Text[$start - 1] -eq "`r") { $start-- }
        }
    } else {
        $hm = [regex]::Match($mask.Substring(0, $start), ',\s*$')
        if ($hm.Success) {
            $start = $hm.Index
        } else {
            # Only key in the object: its line break and indentation go too.
            while ($start -gt 0 -and ($Text[$start - 1] -eq ' ' -or $Text[$start - 1] -eq "`t")) { $start-- }
            if ($start -gt 0 -and $Text[$start - 1] -eq "`n") {
                $start--
                if ($start -gt 0 -and $Text[$start - 1] -eq "`r") { $start-- }
            }
        }
    }
    return $Text.Substring(0, $start) + $Text.Substring($end)
}
