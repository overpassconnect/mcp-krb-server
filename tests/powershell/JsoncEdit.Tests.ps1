# Pester 5 tests for client/JsoncEdit.ps1.
#
# JsoncEdit.ps1 parses and rewrites the user's settings.json by hand, in raw
# text, to preserve their comments and formatting. The mask is the whole trick:
# comment characters become spaces at identical offsets, so a key that appears
# inside a comment is invisible to the search while the real text is spliced at
# the offsets found. These tests cover exactly the cases that masking exists
# for, plus the refusals that keep the editor from corrupting a document it
# does not understand.
#
# Runner: tests/run-tests.sh, which skips these with a message when no
# PowerShell is on PATH; CI runs them on windows-latest so the skip cannot
# quietly become the only outcome.

BeforeAll {
    . (Join-Path $PSScriptRoot '..\..\client\JsoncEdit.ps1')
}

Describe 'Get-JsoncMask' {
    It 'blanks a line comment and keeps offsets aligned' {
        $text = "{`n  // ""remote.SSH.path"": ""commented out""`n}"
        $mask = Get-JsoncMask $text
        $mask.Length | Should -Be $text.Length
        $mask.Contains('commented out') | Should -BeFalse
    }

    It 'blanks a block comment' {
        $mask = Get-JsoncMask '{ /* "hidden": 1 */ }'
        $mask.Contains('hidden') | Should -BeFalse
    }

    It 'leaves string contents intact, including comment markers inside them' {
        $mask = Get-JsoncMask '{ "url": "https://x/a//b" }'
        $mask.Contains('https://x/a//b') | Should -BeTrue
    }

    It 'an escaped quote does not end the string early' {
        $text = '{ "a": "va\"lue // still a string" }'
        $mask = Get-JsoncMask $text
        $mask.Contains('still a string') | Should -BeTrue
    }

    It 'a comment marker after a string is still a comment' {
        $text = "{ ""a"": 1 } // trailing"
        $mask = Get-JsoncMask $text
        $mask.Contains('trailing') | Should -BeFalse
    }
}

Describe 'Test-JsoncValid' {
    It 'accepts comments and trailing commas' {
        $text = "{`n  // a comment`n  ""a"": 1,`n}"
        Test-JsoncValid $text | Should -BeTrue
    }

    It 'rejects a truncated document' {
        Test-JsoncValid '{ "a": ' | Should -BeFalse
    }
}

Describe 'Set-JsoncKey' {
    It 'updates a scalar in place, preserving comments and formatting' {
        $text = "{`n  // keep me`n  ""remote.SSH.path"": ""old"",`n  ""other"": 1`n}"
        $r = Set-JsoncKey -Text $text -Key 'remote.SSH.path' -JsonValue '"new"'
        $r.Contains('// keep me') | Should -BeTrue
        $r.Contains('"remote.SSH.path": "new"') | Should -BeTrue
        $r.Contains('"other": 1') | Should -BeTrue
        Test-JsoncValid $r | Should -BeTrue
    }

    It 'does not match a commented-out copy of the key' {
        $text = "{`n  // ""k"": ""commented"",`n  ""k"": ""real""`n}"
        $r = Set-JsoncKey -Text $text -Key 'k' -JsonValue '"changed"'
        # The live key changes; the commented-out copy is untouched.
        $r.Contains('// "k": "commented",') | Should -BeTrue
        $r.Contains('"k": "changed"') | Should -BeTrue
        $r.Contains('"k": "real"') | Should -BeFalse
    }

    It 'a key that exists only in a comment counts as absent and is inserted' {
        $text = "{`n  // ""k"": 1`n}"
        $r = Set-JsoncKey -Text $text -Key 'k' -JsonValue '2'
        $r.Contains('// "k": 1') | Should -BeTrue
        $r.Contains('"k": 2') | Should -BeTrue
        Test-JsoncValid $r | Should -BeTrue
    }

    It 'a key name mentioned inside a string value is not matched' {
        $text = '{ "note": "mentions remote.SSH.path: here", "remote.SSH.path": "real" }'
        $r = Set-JsoncKey -Text $text -Key 'remote.SSH.path' -JsonValue '"new"'
        $r.Contains('"note": "mentions remote.SSH.path: here"') | Should -BeTrue
        $r.Contains('"remote.SSH.path": "new"') | Should -BeTrue
        Test-JsoncValid $r | Should -BeTrue
    }

    It 'refuses a key whose value is an object rather than corrupt the file' {
        $r = Set-JsoncKey -Text '{ "k": { "nested": 1 } }' -Key 'k' -JsonValue '"x"'
        $r | Should -Be $null
    }

    It 'refuses a key whose value is an array rather than corrupt the file' {
        $r = Set-JsoncKey -Text '{ "k": [1, 2] }' -Key 'k' -JsonValue '"x"'
        $r | Should -Be $null
    }

    It 'refuses a document with no top-level object' {
        Set-JsoncKey -Text 'not json at all' -Key 'k' -JsonValue '1' | Should -Be $null
    }

    It 'inserts after the brace, never inside a leading comment' {
        $text = "// leading comment`n{`n}"
        $r = Set-JsoncKey -Text $text -Key 'k' -JsonValue '1'
        $r.Contains('// leading comment') | Should -BeTrue
        Test-JsoncValid $r | Should -BeTrue
    }

    It 'inserting into a non-empty object keeps the document valid' {
        $r = Set-JsoncKey -Text '{ "a": 1 }' -Key 'k' -JsonValue '2'
        $r.Contains('"k": 2') | Should -BeTrue
        Test-JsoncValid $r | Should -BeTrue
    }

    It 'inserting into an empty object adds no stray comma' {
        $r = Set-JsoncKey -Text '{}' -Key 'k' -JsonValue '1'
        Test-JsoncValid $r | Should -BeTrue
        ($r | Select-String -Pattern ',' -AllMatches).Matches.Count | Should -Be 0
    }
}
