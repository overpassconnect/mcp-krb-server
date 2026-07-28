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
