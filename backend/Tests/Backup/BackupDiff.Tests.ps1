# Aspendora fork (Vikunja CIPP-23): property-level diff of two backups.

BeforeAll {
    . (Join-Path $PSScriptRoot 'BackupFixtures.ps1')
    function Norm { param($V) ConvertTo-CIPPBackupNormalizedValue -Value $V }
    function Items { param([string]$Json) Get-CIPPBackupItemList -Backup (ConvertFrom-TestBackupJson $Json) }
}

Describe 'Compare-CIPPBackupValue' {
    It 'finds nothing between equal values with different key order' {
        $Changes = Compare-CIPPBackupValue -Before (Norm @{ a = 1; b = @{ c = 'x' } }) -After (Norm ([ordered]@{ b = @{ c = 'x' }; a = 1 }))
        @($Changes).Count | Should -Be 0
    }

    It 'reports added, removed and modified properties with dotted paths' {
        $Changes = Compare-CIPPBackupValue -Before (Norm @{ keep = 1; gone = 'old'; nested = @{ v = 1 } }) -After (Norm @{ keep = 1; new = $true; nested = @{ v = 2 } })
        ($Changes | Where-Object Path -EQ 'gone').Change | Should -Be 'Removed'
        ($Changes | Where-Object Path -EQ 'new').Change | Should -Be 'Added'
        $Mod = $Changes | Where-Object Path -EQ 'nested.v'
        $Mod.Change | Should -Be 'Modified'
        $Mod.Before | Should -Be 1
        $Mod.After | Should -Be 2
    }

    It 'treats a reordered array as equal' {
        # These helpers return their array as one pipeline object (return , ...); assign before counting.
        $Changes = Compare-CIPPBackupValue -Before (Norm @{ g = @('a', 'b', 'c') }) -After (Norm @{ g = @('c', 'a', 'b') })
        $Changes.Count | Should -Be 0
    }

    It 'diffs equal-length arrays index by index' {
        $Changes = Compare-CIPPBackupValue -Before (Norm @{ s = @(@{ v = 'on' }, @{ v = 'x' }) }) -After (Norm @{ s = @(@{ v = 'off' }, @{ v = 'x' }) })
        $Changes.Path | Should -Be 's[0].v'
    }

    It 'reports elements only on one side for arrays of different length' {
        $Changes = Compare-CIPPBackupValue -Before (Norm @{ g = @('a', 'b') }) -After (Norm @{ g = @('a', 'b', 'c') })
        $Changes.Path | Should -Be 'g[]'
        $Changes.Change | Should -Be 'Added'
        $Changes.After | Should -Be 'c'
    }
}

Describe 'Compare-CIPPBackupItemSet' {
    It 'classifies policies as Added, Removed, Changed and Unchanged, ignoring volatile fields' {
        $Old = New-TestScheduledBackupJson -Ca @(
            (New-TestCAPolicyJson -Name 'Keep' -Modified '2026-01-01T00:00:00Z'),
            (New-TestCAPolicyJson -Name 'Edit' -State 'enabled'),
            (New-TestCAPolicyJson -Name 'Drop')
        ) -Intune @((New-TestIntuneRow -Name 'Win' -Modified '2026-01-01T00:00:00Z'))
        $New = New-TestScheduledBackupJson -Ca @(
            (New-TestCAPolicyJson -Name 'Keep' -Modified '2026-10-30T00:00:00Z'),
            (New-TestCAPolicyJson -Name 'Edit' -State 'disabled'),
            (New-TestCAPolicyJson -Name 'Add')
        ) -Intune @((New-TestIntuneRow -Name 'Win' -Modified '2026-10-30T00:00:00Z'))

        $Diff = Compare-CIPPBackupItemSet -BaseItems (Items $Old) -CompareItems (Items $New)
        ($Diff | Where-Object Key -EQ 'keep').Status | Should -Be 'Unchanged' # id + modifiedDateTime differ only
        ($Diff | Where-Object Key -EQ 'drop').Status | Should -Be 'Removed'
        ($Diff | Where-Object Key -EQ 'add').Status | Should -Be 'Added'
        $Edit = $Diff | Where-Object Key -EQ 'edit'
        $Edit.Status | Should -Be 'Changed'
        $Edit.Changes.Path | Should -Be 'state'
        $Edit.Changes.Before | Should -Be 'enabled'
        $Edit.Changes.After | Should -Be 'disabled'
        ($Diff | Where-Object Key -EQ 'device|win').Status | Should -Be 'Unchanged' # lastModifiedDateTime, version, @odata.type ignored
        ($Diff | Where-Object Type -EQ 'users' | Where-Object Status -NE 'Unchanged') | Should -BeNullOrEmpty
    }

    It 'reports a changed Intune setting inside the parsed template' {
        $Old = New-TestScheduledBackupJson -Intune @((New-TestIntuneRow -Name 'Win' -Settings @{ passwordMinimumLength = 8 }))
        $New = New-TestScheduledBackupJson -Intune @((New-TestIntuneRow -Name 'Win' -Settings @{ passwordMinimumLength = 14 }))
        $Edit = Compare-CIPPBackupItemSet -BaseItems (Items $Old) -CompareItems (Items $New) | ForEach-Object { $_ } | Where-Object Type -EQ 'intuneconfig'
        $Edit.Status | Should -Be 'Changed'
        $Edit.Changes.Path | Should -Be 'Template.passwordMinimumLength'
    }

    It 'ignores assignments unless asked' {
        $A = New-TestCatalogRow -Name 'Cat'
        $B = New-TestCatalogRow -Name 'Cat'
        $T = $B.TemplateJson | ConvertFrom-Json
        $T.assignments = @(@{ target = @{ groupId = 'g-2' } })
        $B.TemplateJson = $T | ConvertTo-Json -Depth 20 -Compress
        $Old = Items (New-TestScheduledBackupJson -Intune @($A))
        $New = Items (New-TestScheduledBackupJson -Intune @($B))
        (Compare-CIPPBackupItemSet -BaseItems $Old -CompareItems $New | ForEach-Object { $_ } | Where-Object Type -EQ 'intuneconfig').Status | Should -Be 'Unchanged'
        $WithAssignments = Compare-CIPPBackupItemSet -BaseItems $Old -CompareItems $New -IncludeAssignments | ForEach-Object { $_ } | Where-Object Type -EQ 'intuneconfig'
        $WithAssignments.Status | Should -Be 'Changed'
        $WithAssignments.Changes.Path | Should -BeLike 'Template.assignments*'
    }

    It 'matches users by object id and shows property changes' {
        $Old = New-TestScheduledBackupJson
        $New = New-TestScheduledBackupJson -Users @(
            [pscustomobject]@{ id = 'u1'; userPrincipalName = 'ann@contoso.com'; displayName = 'Ann'; jobTitle = 'CEO' },
            [pscustomobject]@{ id = 'u2'; userPrincipalName = 'bob@contoso.com'; displayName = 'Bob'; jobTitle = 'Clerk' }
        )
        $Ann = Compare-CIPPBackupItemSet -BaseItems (Items $Old) -CompareItems (Items $New) | ForEach-Object { $_ } | Where-Object Key -EQ 'u1'
        $Ann.Status | Should -Be 'Changed'
        $Ann.Changes.Path | Should -Be 'jobTitle'
    }
}
