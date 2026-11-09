# Pester 5 tests for the step of client/setup.ps1 that puts the realm CA into
# Windows' trust store.
#
# setup.ps1 provisions a whole workstation when it runs, so Add-RealmCaToStore is
# lifted out of it through the parser and run on its own, against a throwaway
# store under CurrentUser: nothing that decides trust on the machine running the
# tests is touched, and what is tested is the function as setup.ps1 ships it.

BeforeAll {
    $setup = Join-Path $PSScriptRoot '..\..\client\setup.ps1'
    $ast = [Management.Automation.Language.Parser]::ParseFile($setup, [ref]$null, [ref]$null)
    $fn = $ast.Find({
        param($n)
        $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Add-RealmCaToStore'
    }, $true)
    if (-not $fn) { throw 'Add-RealmCaToStore is not in setup.ps1' }
    . ([scriptblock]::Create($fn.Extent.Text))

    # A self-signed CA certificate written as PEM with LF line endings, as IPA
    # serves ca.crt, and the SHA-256 of that file, which is what -CaSha256 pins.
    function New-CaFile {
        $rsa = [Security.Cryptography.RSA]::Create(2048)
        $req = [Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Test Realm CA', $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $cert = $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays(1))
        $b64 = [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks') -replace "`r`n", "`n"
        $path = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.crt')
        [IO.File]::WriteAllText($path, "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n")
        [pscustomobject]@{
            Path       = $path
            Thumbprint = $cert.Thumbprint
            Sha256     = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLower()
        }
    }
}

Describe 'setup.ps1 Add-RealmCaToStore' {
    BeforeEach {
        $name = 'McpKrbTest' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $s = New-Object Security.Cryptography.X509Certificates.X509Store($name, 'CurrentUser')
        $s.Open('ReadWrite')
        $s.Close()
        $store = "Cert:\CurrentUser\$name"
        $ca = New-CaFile
    }
    AfterEach {
        # The Cert: drive refuses to delete a store under CurrentUser, and such
        # a store is a key under HKCU, so the key is what goes.
        Remove-Item -Path "HKCU:\Software\Microsoft\SystemCertificates\$name" -Recurse -ErrorAction SilentlyContinue
    }

    It 'adds the pinned CA and returns its thumbprint for the manifest' {
        Add-RealmCaToStore -Path $ca.Path -Sha256 $ca.Sha256 -Store $store | Should -Be $ca.Thumbprint
        (Join-Path $store $ca.Thumbprint) | Should -Exist
    }

    It 'returns nothing for a CA already there, so it is never recorded as the kit''s' {
        $null = Add-RealmCaToStore -Path $ca.Path -Sha256 $ca.Sha256 -Store $store
        Add-RealmCaToStore -Path $ca.Path -Sha256 $ca.Sha256 -Store $store | Should -BeNullOrEmpty
        (Join-Path $store $ca.Thumbprint) | Should -Exist
    }

    It 'takes the pin in upper case too' {
        Add-RealmCaToStore -Path $ca.Path -Sha256 $ca.Sha256.ToUpper() -Store $store | Should -Be $ca.Thumbprint
    }

    It 'refuses a CA that does not match the pin, and adds nothing' {
        { Add-RealmCaToStore -Path $ca.Path -Sha256 ('0' * 64) -Store $store } |
            Should -Throw '*does not match -CaSha256*'
        (Join-Path $store $ca.Thumbprint) | Should -Not -Exist
    }
}
