# Aspendora fork (Vikunja CIPP-23): canonical hashing, manifest and verification of tenant backups.

BeforeAll {
    . (Join-Path $PSScriptRoot 'BackupFixtures.ps1')

    function New-Entity {
        param($Manifest, [string]$ManifestJson)
        [pscustomobject]@{
            RowKey         = 'contoso.com_2026-10-31-0100'
            HashVersion    = 1
            BackupSha256   = $Manifest.BackupSha256
            ManifestSha256 = Get-CIPPBackupSha256 -Text $ManifestJson
            ItemCounts     = ($Manifest.ItemCounts | ConvertTo-Json -Compress)
        }
    }
    # Writes a manifest the way New-CIPPBackup does and reads it back the way verification does.
    function New-RoundTrippedManifest {
        param([string]$Json)
        $Manifest = New-CIPPBackupManifest -BackupJson $Json
        $ManifestJson = ConvertTo-Json -InputObject $Manifest -Depth 20 -Compress
        [pscustomobject]@{ Json = $ManifestJson; Parsed = ($ManifestJson | ConvertFrom-Json -Depth 100); Built = $Manifest }
    }
}

Describe 'Canonical JSON' {
    It 'is independent of property order' {
        $A = [pscustomobject][ordered]@{ b = 1; a = @{ y = 'x'; x = @(1, 2) } }
        $B = [pscustomobject][ordered]@{ a = [ordered]@{ x = @(1, 2); y = 'x' }; b = 1 }
        ConvertTo-CIPPBackupCanonicalJson -Value $A | Should -Be (ConvertTo-CIPPBackupCanonicalJson -Value $B)
        ConvertTo-CIPPBackupCanonicalJson -Value $A | Should -Be '{"a":{"x":[1,2],"y":"x"},"b":1}'
    }

    It 'keeps single-element and empty arrays as arrays' {
        ConvertTo-CIPPBackupCanonicalJson -Value @{ one = @('a'); none = @() } | Should -Be '{"none":[],"one":["a"]}'
    }

    It 'survives a ConvertTo-Json / ConvertFrom-Json round trip unchanged' {
        $Original = [pscustomobject]@{ name = "Quote "" and \ slash"; when = '2026-10-31T05:00:00Z'; n = 1.5; flag = $false; nested = @([pscustomobject]@{ z = 1; a = $null }) }
        $RoundTripped = $Original | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10 -NoEnumerate
        (ConvertTo-CIPPBackupCanonicalJson -Value $RoundTripped) | Should -Be (ConvertTo-CIPPBackupCanonicalJson -Value ($RoundTripped | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10 -NoEnumerate))
    }

    It 'escapes control characters deterministically' {
        ConvertTo-CIPPBackupCanonicalJson -Value "a`tb" | Should -Be '"a\u0009b"'
    }

    It 'hashes UTF-8 bytes and ignores a leading BOM' {
        Get-CIPPBackupSha256 -Text 'abc' | Should -Be 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
        Get-CIPPBackupSha256 -Text ([char]0xFEFF + 'abc') | Should -Be (Get-CIPPBackupSha256 -Text 'abc')
    }
}

Describe 'Get-CIPPBackupItemList' {
    It 'unpacks every component shape of a scheduled backup with stable keys' {
        $Items = Get-CIPPBackupItemList -Backup (ConvertFrom-TestBackupJson (New-TestScheduledBackupJson))
        ($Items | Where-Object Type -EQ 'users').Key | Should -Be @('u1', 'u2')
        ($Items | Where-Object Type -EQ 'users')[0].AltKey | Should -Be 'ann@contoso.com'
        ($Items | Where-Object Type -EQ 'ca').Key | Should -Be 'require mfa'
        ($Items | Where-Object Type -EQ 'ca').Content.state | Should -Be 'enabled'
        ($Items | Where-Object Type -EQ 'intuneconfig').Key | Should -Be 'device|win - baseline'
        ($Items | Where-Object Type -EQ 'antispam').Key | Should -Be 'policy|default'
        $Items | Where-Object Type -In 'PartitionKey', 'RowKey', 'TenantFilter' | Should -BeNullOrEmpty
    }

    It 'names Settings Catalog policies from the payload, as Set-CIPPIntunePolicy does' {
        $Row = New-TestCatalogRow -Name 'Payload Name'
        $Row.DisplayName = 'Column Name'
        $Items = Get-CIPPBackupItemList -Backup (ConvertFrom-TestBackupJson (New-TestScheduledBackupJson -Intune @($Row)))
        ($Items | Where-Object Type -EQ 'intuneconfig').Key | Should -Be 'catalog|payload name'
    }

    It 'marks capture error strings as unparsed instead of failing' {
        $Json = New-TestScheduledBackupJson -Ca @('Failed to create a template of the Conditional Access Policy with ID: x. Error: boom')
        $Ca = Get-CIPPBackupItemList -Backup (ConvertFrom-TestBackupJson $Json) | ForEach-Object { $_ } | Where-Object Type -EQ 'ca'
        $Ca.Unparsed | Should -BeTrue
        $Ca.Key | Should -BeLike 'unparsed|*'
    }

    It 'makes duplicate keys unique' {
        $Json = New-TestScheduledBackupJson -Ca @((New-TestCAPolicyJson -Name 'Dup'), (New-TestCAPolicyJson -Name 'DUP'))
        (Get-CIPPBackupItemList -Backup (ConvertFrom-TestBackupJson $Json) | ForEach-Object { $_ } | Where-Object Type -EQ 'ca').Key | Should -Be @('dup', 'dup #2')
    }

    It 'groups CIPP core backups by table' {
        $Rows = @(
            [pscustomobject]@{ table = 'Config'; PartitionKey = 'p'; RowKey = 'r1'; Value = 1 },
            [pscustomobject]@{ table = 'templates'; PartitionKey = 'IntuneTemplate'; RowKey = 'r2' }
        ) | ConvertTo-Json -Depth 5 | ConvertFrom-Json -NoEnumerate
        $Items = Get-CIPPBackupItemList -Backup $Rows
        $Items.Type | Should -Be @('Config', 'templates')
        $Items[0].Key | Should -Be 'p|r1'
    }
}

Describe 'Backup manifest and verification' {
    BeforeEach {
        $script:Json = New-TestScheduledBackupJson
        $script:M = New-RoundTrippedManifest -Json $script:Json
        $script:Entity = New-Entity -Manifest $script:M.Built -ManifestJson $script:M.Json
    }

    It 'records a file hash, per-item hashes and counts' {
        $script:M.Built.HashVersion | Should -Be 1
        $script:M.Built.BackupSha256 | Should -Be (Get-CIPPBackupSha256 -Text $script:Json)
        $script:M.Built.ItemCounts['users'] | Should -Be 2
        $script:M.Built.ItemCounts['ca'] | Should -Be 1
        ($script:M.Built.Types | Where-Object { $_.Type -eq 'users' }).Items.Count | Should -Be 2
    }

    It 'verifies an untouched backup' {
        $R = Test-CIPPBackupIntegrity -BackupJson $script:Json -Manifest $script:M.Parsed -ManifestJson $script:M.Json -Entity $script:Entity
        $R.Status | Should -Be 'Verified'
        $R.Types | Where-Object Status -NE 'Verified' | Should -BeNullOrEmpty
    }

    It 'keeps item hashes valid when the file is re-serialised with different formatting, but flags the file' {
        $Reordered = ConvertFrom-TestBackupJson $script:Json | ConvertTo-Json -Depth 50
        $R = Test-CIPPBackupIntegrity -BackupJson $Reordered -Manifest $script:M.Parsed -ManifestJson $script:M.Json -Entity $script:Entity
        ($R.Types | Where-Object Status -NE 'Verified') | Should -BeNullOrEmpty
        # ...but the file itself changed, so the overall result is not Verified.
        $R.Status | Should -Be 'Corrupt'
        $R.Detail | Should -BeLike '*file bytes changed*'
    }

    It 'reports a changed item as Corrupt and names it' {
        $Tampered = $script:Json.Replace('"jobTitle":"Clerk"', '"jobTitle":"Owner"')
        $R = Test-CIPPBackupIntegrity -BackupJson $Tampered -Manifest $script:M.Parsed -ManifestJson $script:M.Json -Entity $script:Entity
        $R.Status | Should -Be 'Corrupt'
        ($R.Types | Where-Object Type -EQ 'users').Corrupt | Should -Be @('u2')
    }

    It 'reports a removed item as Missing' {
        $Backup = ConvertFrom-TestBackupJson $script:Json
        $Backup.users = @($Backup.users[0])
        $R = Test-CIPPBackupIntegrity -BackupJson ($Backup | ConvertTo-Json -Depth 50 -Compress) -Manifest $script:M.Parsed -ManifestJson $script:M.Json -Entity $script:Entity
        $R.Status | Should -Be 'Missing'
        ($R.Types | Where-Object Type -EQ 'users').Missing | Should -Be @('u2')
        ($R.Types | Where-Object Type -EQ 'users').ActualCount | Should -Be 1
    }

    It 'reports a count mismatch when only the row counts are available and an item was added' {
        $Backup = ConvertFrom-TestBackupJson $script:Json
        $Backup.users = @($Backup.users) + @([pscustomobject]@{ id = 'u3'; userPrincipalName = 'cy@contoso.com' })
        $Changed = $Backup | ConvertTo-Json -Depth 50 -Compress
        $NoFileHash = $script:Entity.PSObject.Copy()
        $NoFileHash.BackupSha256 = $null
        $R = Test-CIPPBackupIntegrity -BackupJson $Changed -Manifest $null -ManifestJson $null -Entity $NoFileHash
        $R.Status | Should -Be 'CountMismatch'
        ($R.Types | Where-Object Type -EQ 'users').ExpectedCount | Should -Be 2
    }

    It 'flags a manifest that does not match the hash on the row' {
        $R = Test-CIPPBackupIntegrity -BackupJson $script:Json -Manifest $script:M.Parsed -ManifestJson ($script:M.Json + ' ') -Entity $script:Entity
        $R.Status | Should -Be 'Corrupt'
    }

    It 'still verifies from the row when the manifest blob is gone' {
        $R = Test-CIPPBackupIntegrity -BackupJson $script:Json -Manifest $null -ManifestJson $null -Entity $script:Entity
        $R.Status | Should -Be 'Verified'
        $R.ManifestFound | Should -BeFalse
    }

    It 'reports an unreadable file as Missing and invalid JSON as Corrupt' {
        (Test-CIPPBackupIntegrity -BackupJson $null -Manifest $script:M.Parsed -Entity $script:Entity).Status | Should -Be 'Missing'
        (Test-CIPPBackupIntegrity -BackupJson '{"users":[' -Manifest $script:M.Parsed -Entity $script:Entity).Status | Should -Be 'Corrupt'
    }

    It 'reports backups written before hashing as unverified (pre-hash) with counts' {
        $Legacy = [pscustomobject]@{ RowKey = 'contoso.com_2025-01-01-0100' }
        $R = Test-CIPPBackupIntegrity -BackupJson $script:Json -Manifest $null -ManifestJson $null -Entity $Legacy
        $R.Status | Should -Be 'Unverified (pre-hash)'
        ($R.Types | Where-Object Type -EQ 'users').ActualCount | Should -Be 2
    }
}
