# Pester 5 tests for client/uninstall.ps1.
#
# The script runs in a child powershell against a synthetic user-profile tree
# (its test-hook parameters), so `exit` in its error paths cannot take the test
# runner down with it, and nothing on the machine running the tests is touched.
# The wsl.exe stub records its arguments, which is how the -d assertion and the
# never---unregister assertion are made against what would really be executed.

BeforeAll {
    $script:Script = Join-Path $PSScriptRoot '..\..\client\uninstall.ps1'

    function New-Tree {
        param([string]$Root)
        New-Item -ItemType Directory -Force (Join-Path $Root 'bin') | Out-Null
        $code = Join-Path $Root 'AppData\Roaming\Code\User'
        New-Item -ItemType Directory -Force $code | Out-Null
        Set-Content -Path (Join-Path $Root 'bin\ssh-dispatch.bat') -Value '@echo off'
        @(
            'function wslssh { ssh my-own-thing @args }'
            'function wslssh { wsl.exe -e ssh @args }   # Kerberos ssh via WSL (setup.ps1)'
            'function mcp-fetch { my own version }'
            'function mcp-fetch { wsl.exe -e mcp-fetch @args }   # Kerberos fetch via WSL (setup.ps1)'
        ) | Set-Content -Path (Join-Path $Root 'profile.ps1')
        @(
            '{'
            '    // the user''s own comment'
            '    "editor.fontSize": 14,'
            '    "remote.SSH.path": "C:\\Users\\x\\bin\\ssh-dispatch.bat",'
            '    "remote.SSH.useLocalServer": false,'
            '    "remote.SSH.enableDynamicForwarding": false'
            '}'
        ) | Set-Content -Path (Join-Path $code 'settings.json')
        Set-Content -Path (Join-Path $Root '.claude.json') -Value (
            '{"mcpServers":{"internal-tools":{"type":"stdio"},"other-server":{"type":"stdio"}},"unrelated":1}')
        # A wsl.exe stand-in that records exactly what would have run.
        Set-Content -Path (Join-Path $Root 'wsl-stub.cmd') -Encoding ascii -Value @(
            '@echo off'
            'echo %* >> "%~dp0wsl-args.log"'
        )
        $manifest = @{
            manifest_version         = 1
            written_by               = 'setup.ps1'
            created                  = @((Join-Path $Root 'bin\ssh-dispatch.bat'))
            created_dirs             = @((Join-Path $Root 'bin'))
            packages_installed       = @()
            packages_already_present = @()
            replaced                 = @{}
            prior_values             = @{
                (Join-Path $code 'settings.json') = @{
                    'remote.SSH.path'                    = $null
                    'remote.SSH.useLocalServer'          = 'true'
                    'remote.SSH.enableDynamicForwarding' = $null
                }
            }
            claude_registration      = 'internal-tools'
            wsl_distro               = 'Ubuntu-Test'
        }
        Set-Content -Path (Join-Path $Root 'bin\mcp-krb-manifest.json') `
            -Value ($manifest | ConvertTo-Json -Depth 6)
        $code
    }

    function Invoke-Uninstall {
        param([string]$Root, [string[]]$Extra = @())
        $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script:Script,
                    '-UserProfile', $Root,
                    '-ManifestPath', (Join-Path $Root 'bin\mcp-krb-manifest.json'),
                    '-ProfilePath', (Join-Path $Root 'profile.ps1'),
                    '-WslCommand', (Join-Path $Root 'wsl-stub.cmd')) + $Extra
        $out = & powershell @psArgs 2>&1 | Out-String
        [pscustomobject]@{ Out = $out; Code = $LASTEXITCODE }
    }
}

Describe 'uninstall.ps1' {
    BeforeEach {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N').Substring(0, 8))
        $codeDir = New-Tree -Root $root
        $settings = Join-Path $codeDir 'settings.json'
    }

    It 'defaults to a dry run that touches nothing' {
        $r = Invoke-Uninstall -Root $root
        $r.Code | Should -Be 0
        $r.Out | Should -Match 'DRY RUN'
        (Join-Path $root 'bin\ssh-dispatch.bat') | Should -Exist
        (Get-Content -Raw $settings) | Should -Match 'remote\.SSH\.path'
        (Get-Content -Raw (Join-Path $root '.claude.json')) | Should -Match 'internal-tools'
    }

    It 'a null prior value removes the key; a string prior restores it verbatim' {
        $r = Invoke-Uninstall -Root $root -Extra @('-Yes')
        $r.Code | Should -Be 0
        $after = Get-Content -Raw $settings
        $after | Should -Not -Match 'remote\.SSH\.path'
        $after | Should -Not -Match 'enableDynamicForwarding'
        $after | Should -Match '"remote\.SSH\.useLocalServer": true'
        # the user's own content and comments survive the restore
        $after | Should -Match 'the user''s own comment'
        $after | Should -Match '"editor\.fontSize": 14'
    }

    It 'removes what the manifest says the installer created, then the manifest' {
        $r = Invoke-Uninstall -Root $root -Extra @('-Yes')
        $r.Code | Should -Be 0
        (Join-Path $root 'bin\ssh-dispatch.bat') | Should -Not -Exist
        (Join-Path $root 'bin\mcp-krb-manifest.json') | Should -Not -Exist
        (Join-Path $root 'bin') | Should -Not -Exist   # created_dirs, now empty
    }

    It 'a user-authored wslssh without the marker comment survives' {
        $r = Invoke-Uninstall -Root $root -Extra @('-Yes')
        $r.Code | Should -Be 0
        $profile = Get-Content -Raw (Join-Path $root 'profile.ps1')
        $profile | Should -Match 'my-own-thing'
        $profile | Should -Not -Match 'Kerberos ssh via WSL'
    }

    It 'every function setup.ps1 writes has a marker uninstall knows' {
        # Each `function` line setup.ps1 appends to the profile carries a
        # marker comment, and uninstall.ps1 matches on those markers. A
        # function added to one without the other is invisible to uninstall,
        # which is how a shim outlives the kit that installed it.
        $setup = Get-Content -Raw (Join-Path $PSScriptRoot '..\..\client\setup.ps1')
        $written = [regex]::Matches($setup, '\$kept \+= "function [^"]*# ([^"(]*\(setup\.ps1\))"')
        $written.Count | Should -BeGreaterThan 1
        $known = Get-Content -Raw $script:Script
        foreach ($m in $written) {
            $known | Should -Match ([regex]::Escape("# " + $m.Groups[1].Value))
        }
    }

    It 'the mcp-fetch line goes, and a user-authored one stays' {
        $r = Invoke-Uninstall -Root $root -Extra @('-Yes')
        $r.Code | Should -Be 0
        $profile = Get-Content -Raw (Join-Path $root 'profile.ps1')
        $profile | Should -Match 'my own version'
        $profile | Should -Not -Match 'Kerberos fetch via WSL'
    }

    It 'removes only the recorded entry from .claude.json' {
        $r = Invoke-Uninstall -Root $root -Extra @('-Yes')
        $r.Code | Should -Be 0
        $cfg = Get-Content -Raw (Join-Path $root '.claude.json') | ConvertFrom-Json
        $cfg.mcpServers.PSObject.Properties.Name | Should -Not -Contain 'internal-tools'
        $cfg.mcpServers.PSObject.Properties.Name | Should -Contain 'other-server'
        $cfg.unrelated | Should -Be 1
    }

    It 'the WSL call carries -d with the distro from the manifest' {
        $r = Invoke-Uninstall -Root $root -Extra @('-Yes')
        $r.Code | Should -Be 0
        $log = Get-Content -Raw (Join-Path $root 'wsl-args.log')
        $log | Should -Match '-d Ubuntu-Test'
        $log | Should -Match '-u root'
        $log | Should -Not -Match '--unregister'
    }

    It 'refuses to run without a manifest and removes nothing' {
        Remove-Item (Join-Path $root 'bin\mcp-krb-manifest.json')
        $r = Invoke-Uninstall -Root $root -Extra @('-Yes')
        $r.Code | Should -Be 1
        (Join-Path $root 'bin\ssh-dispatch.bat') | Should -Exist
        (Get-Content -Raw $settings) | Should -Match 'remote\.SSH\.path'
    }

    It 'refuses a manifest that does not parse' {
        Set-Content -Path (Join-Path $root 'bin\mcp-krb-manifest.json') -Value '{broken'
        $r = Invoke-Uninstall -Root $root -Extra @('-Yes')
        $r.Code | Should -Be 1
        (Join-Path $root 'bin\ssh-dispatch.bat') | Should -Exist
    }

    It 'reports .bak files instead of deleting them' {
        Set-Content -Path ($settings + '.bak') -Value 'old backup, maybe not ours'
        $r = Invoke-Uninstall -Root $root -Extra @('-Yes')
        $r.Code | Should -Be 0
        ($settings + '.bak') | Should -Exist
        $r.Out | Should -Match 'left in place'
    }

    It 'no code path calls wsl --unregister' {
        # Static guard, same idea as the ipa-client-install test on the sh
        # side: every mention must be prose (comment or printed line).
        foreach ($line in (Get-Content $script:Script | Where-Object { $_ -match '--unregister' })) {
            $t = $line.Trim()
            ($t.StartsWith('#') -or $t.StartsWith('Say') -or $t.StartsWith('Warn')) |
                Should -BeTrue -Because "line looks executable: $line"
        }
    }
}
