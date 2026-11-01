# Pester tests for Get-CIPPEntraRecoveryCoverage (Vikunja CIPP-17).
# Pins how scheduled CIPP backup tasks are resolved to tenants (direct by any identifier, AllTenants with exclusions,
# tenant groups), the gap rules and status, the latest-backup pick (Timestamp, RowKey fallback, -partN rows ignored),
# the licence gate and the native snapshot / soft-deleted CA reads, and that SkipLive makes no Graph calls.
# Storage and Graph are stubbed; nothing reads $env.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Get-CIPPEntraRecoveryCoverage.ps1')

    function Get-Tenants { [CmdletBinding()] param($TenantFilter, [switch]$IncludeErrors) }
    function Get-CIPPTable { [CmdletBinding()] param($TableName) }
    function Get-CIPPAzDataTableEntity { [CmdletBinding()] param($TableName, $Filter, $Property) }
    function Expand-CIPPTenantGroups { [CmdletBinding()] param($TenantFilter) }
    function Get-CIPPTenantCapabilities { [CmdletBinding()] param($TenantFilter) }
    function New-GraphBulkRequest { [CmdletBinding()] param($Requests, $tenantid, $asapp, $Version) }
    function Get-CippException { [CmdletBinding()] param($Exception) @{ NormalizedError = "$Exception" } }

    $script:TenantA = [pscustomobject]@{ defaultDomainName = 'a.com'; initialDomainName = 'a.onmicrosoft.com'; customerId = 'aaaa'; displayName = 'Alpha' }
    $script:TenantB = [pscustomobject]@{ defaultDomainName = 'b.com'; initialDomainName = 'b.onmicrosoft.com'; customerId = 'bbbb'; displayName = 'Bravo' }

    $script:AllComponents = [ordered]@{ users = $true; groups = $true; ca = $true; intuneconfig = $true; antispam = $false }

    function script:New-Task {
        param([string]$Name = 'CIPP Backup', [string]$Tenant, $Components = $script:AllComponents, [string]$BackupType = 'Scheduled',
            [string]$Tenants, [string]$TenantGroup, [string]$Excluded, [switch]$Disabled, [switch]$SelectionVersion)
        $Row = [ordered]@{
            PartitionKey = 'ScheduledTask'; RowKey = [guid]::NewGuid().ToString(); Name = $Name; Command = 'New-CIPPBackup'
            Tenant = $Tenant; TaskState = 'Planned'; Recurrence = '1d'
            # Stored as a JSON string, as AddScheduledItem writes it.
            Parameters = (@{ backupType = $BackupType; ScheduledBackupValues = $Components } | ConvertTo-Json -Depth 5 -Compress)
        }
        if ($Tenants) { $Row.Tenants = $Tenants }
        if ($TenantGroup) { $Row.TenantGroup = $TenantGroup }
        if ($Excluded) { $Row.excludedTenants = $Excluded }
        if ($Disabled) { $Row.Disabled = $true }
        if ($SelectionVersion) { $Row.TenantSelectionVersion = 2 }
        [pscustomobject]$Row
    }

    function script:New-Backup {
        param([string]$Tenant, [double]$DaysAgo, $ItemCounts, [string]$RowKey, [switch]$NoTimestamp, [switch]$NoTenantColumn)
        $When = [datetime]::UtcNow.AddDays(-$DaysAgo)
        $Row = [ordered]@{
            PartitionKey = 'ScheduledBackup'
            RowKey       = if ($RowKey) { $RowKey } else { "$($Tenant)_$($When.ToString('yyyy-MM-dd-HHmm'))" }
        }
        # Table storage hands back Timestamp as a DateTimeOffset.
        if (-not $NoTimestamp) { $Row.Timestamp = [datetimeoffset]$When }
        if (-not $NoTenantColumn) { $Row.TenantFilter = $Tenant }
        if ($ItemCounts) { $Row.ItemCounts = ($ItemCounts | ConvertTo-Json -Compress) }
        [pscustomobject]$Row
    }

    function script:Set-Fixture {
        param($Tenants = @($script:TenantA), $Tasks = @(), $Backups = @(), $Caps = @{}, $Bulk = @{}, $Groups = @{})
        $script:F = @{ Tenants = @($Tenants); Tasks = @($Tasks); Backups = @($Backups); Caps = $Caps; Bulk = $Bulk; Groups = $Groups }
    }
}

Describe 'Get-CIPPEntraRecoveryCoverage' {
    BeforeEach {
        $script:BulkCalls = [System.Collections.Generic.List[object]]::new()
        Mock Get-Tenants {
            if ($TenantFilter) { return @($script:F.Tenants | Where-Object { $TenantFilter -in @($_.defaultDomainName, $_.initialDomainName, $_.customerId) }) }
            $script:F.Tenants
        }
        Mock Get-CIPPTable { @{ TableName = $TableName } }
        Mock Get-CIPPAzDataTableEntity {
            if ($TableName -eq 'ScheduledTasks') { return $script:F.Tasks }
            if ($TableName -eq 'ScheduledBackup') { $script:BackupProperty = $Property; return $script:F.Backups }
            throw "unexpected table $TableName"
        }
        Mock Expand-CIPPTenantGroups {
            foreach ($Entry in @($TenantFilter)) {
                if ($Entry.type -eq 'Group' -and $script:F.Groups.ContainsKey([string]$Entry.value)) {
                    foreach ($M in $script:F.Groups[[string]$Entry.value]) { [pscustomobject]@{ value = $M; label = $M } }
                } else { [pscustomobject]@{ value = $Entry.value; label = $Entry.label } }
            }
        }
        Mock Get-CIPPTenantCapabilities {
            if ($script:F.Caps.ContainsKey($TenantFilter)) { return [pscustomobject]$script:F.Caps[$TenantFilter] }
            [pscustomobject]@{ AAD_PREMIUM = $true; AAD_PREMIUM_P2 = $false }
        }
        Mock New-GraphBulkRequest {
            $script:BulkCalls.Add([pscustomobject]@{ Tenant = $tenantid; Ids = @($Requests.id); AsApp = $asapp; Version = $Version })
            $Fixture = $script:F.Bulk[$tenantid]
            foreach ($R in $Requests) {
                $Entry = if ($Fixture -and $Fixture.ContainsKey($R.id)) { $Fixture[$R.id] } else { @{ status = 200; value = @() } }
                [pscustomobject]@{ id = $R.id; status = $Entry.status; body = [pscustomobject]@{ value = @($Entry.value) } }
            }
        }
    }

    Context 'CIPP backup coverage' {
        It 'reports a Gap with code NoTask when no scheduled CIPP backup exists (the state on 2026-11-01)' {
            Set-Fixture
            $R = Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive
            @($R.Rows).Count | Should -Be 1
            $R.Rows[0].cippStatus | Should -Be 'Gap'
            $R.Rows[0].gapCodes | Should -Be @('NoTask')
            $R.Rows[0].gaps | Should -Be 'No scheduled CIPP backup'
            $R.Rows[0].cippLastBackup | Should -BeNullOrEmpty
            $R.Summary.CippGap | Should -Be 1
        }

        It 'reports Covered for a direct task with CA, users and groups and a backup from today' {
            Set-Fixture -Tasks @(New-Task -Tenant 'a.com') -Backups @(
                (New-Backup -Tenant 'a.com' -DaysAgo 3),
                (New-Backup -Tenant 'a.com' -DaysAgo 0.2 -ItemCounts ([ordered]@{ users = 40; ca = 12 }))
            )
            $Row = (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive).Rows[0]
            $Row.cippStatus | Should -Be 'Covered'
            $Row.gaps | Should -BeNullOrEmpty
            @($Row.gapCodes).Count | Should -Be 0
            $Row.cippComponents | Should -Be 'ca, groups, intuneconfig, users'
            $Row.cippBackupCount | Should -Be 2
            $Row.cippLastBackupAgeDays | Should -BeLessThan 1
            $Row.cippLastBackupItems | Should -Be 'ca: 12, users: 40'
            $Row.cippTasks | Should -Be 'CIPP Backup'
            $script:BackupProperty | Should -Not -Contain 'Backup'
        }

        It 'matches a task stored against the initial domain or customer id' {
            Set-Fixture -Tasks @(New-Task -Tenant 'aaaa') -Backups @(New-Backup -Tenant 'a.onmicrosoft.com' -DaysAgo 0.5)
            $Row = (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive).Rows[0]
            $Row.cippStatus | Should -Be 'Covered'
            $Row.cippBackupCount | Should -Be 1
        }

        It 'applies an AllTenants task to every tenant except the excluded ones' {
            Set-Fixture -Tenants @($script:TenantA, $script:TenantB) -Tasks @(New-Task -Tenant 'AllTenants' -Excluded 'b.com') -Backups @(New-Backup -Tenant 'a.com' -DaysAgo 0.5)
            $R = Get-CIPPEntraRecoveryCoverage -TenantFilter 'AllTenants' -SkipLive
            ($R.Rows | Where-Object tenant -EQ 'a.com').cippStatus | Should -Be 'Covered'
            ($R.Rows | Where-Object tenant -EQ 'b.com').gapCodes | Should -Be @('NoTask')
            $R.Summary.Tenants | Should -Be 2
        }

        It 'resolves a tenant-group task through Expand-CIPPTenantGroups' {
            $Group = '[{"type":"Group","value":"grp1","label":"Clients"}]'
            Set-Fixture -Tenants @($script:TenantA, $script:TenantB) -Tasks @(New-Task -Tenant 'AllTenants' -TenantGroup $Group) -Groups @{ grp1 = @('b.com') } -Backups @(New-Backup -Tenant 'b.com' -DaysAgo 1)
            $R = Get-CIPPEntraRecoveryCoverage -TenantFilter 'AllTenants' -SkipLive
            ($R.Rows | Where-Object tenant -EQ 'b.com').cippStatus | Should -Be 'Covered'
            ($R.Rows | Where-Object tenant -EQ 'a.com').cippStatus | Should -Be 'Gap'
        }

        It 'ignores legacy snapshot exclusions on a stored selection, as the scheduler does' {
            $Selection = '[{"type":"Tenant","value":"a.com","label":"a"}]'
            Set-Fixture -Tasks @(New-Task -Tenant 'AllTenants' -Tenants $Selection -Excluded 'a.com') -Backups @(New-Backup -Tenant 'a.com' -DaysAgo 0.5)
            (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive).Rows[0].cippStatus | Should -Be 'Covered'
        }

        It 'honours exclusions on a versioned stored selection' {
            $Selection = '[{"type":"Tenant","value":"a.com","label":"a"}]'
            Set-Fixture -Tasks @(New-Task -Tenant 'AllTenants' -Tenants $Selection -Excluded 'a.com' -SelectionVersion) -Backups @(New-Backup -Tenant 'a.com' -DaysAgo 0.5)
            (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive).Rows[0].gapCodes | Should -Be @('NoTask')
        }

        It 'flags a disabled task and does not count its components' {
            Set-Fixture -Tasks @(New-Task -Tenant 'a.com' -Disabled) -Backups @(New-Backup -Tenant 'a.com' -DaysAgo 0.5)
            $Row = (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive).Rows[0]
            $Row.cippStatus | Should -Be 'Gap'
            $Row.gapCodes | Should -Be @('TaskDisabled')
            $Row.cippComponents | Should -BeNullOrEmpty
            $Row.cippTasks | Should -Be 'CIPP Backup (disabled)'
        }

        It 'flags a task that has never produced a backup' {
            Set-Fixture -Tasks @(New-Task -Tenant 'a.com')
            $Row = (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive).Rows[0]
            $Row.gapCodes | Should -Be @('NoBackup')
            $Row.cippStatus | Should -Be 'Gap'
        }

        It 'flags a backup older than MaxBackupAgeDays' {
            Set-Fixture -Tasks @(New-Task -Tenant 'a.com') -Backups @(New-Backup -Tenant 'a.com' -DaysAgo 9)
            $Row = (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -MaxBackupAgeDays 7 -SkipLive).Rows[0]
            $Row.gapCodes | Should -Be @('Stale')
            $Row.gaps | Should -BeLike 'Last CIPP backup is 9* days old'
            (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -MaxBackupAgeDays 10 -SkipLive).Rows[0].cippStatus | Should -Be 'Covered'
        }

        It 'reports Partial when Conditional Access or users/groups are left out' {
            Set-Fixture -Tasks @(New-Task -Tenant 'a.com' -Components ([ordered]@{ users = $true; groups = $false; ca = $false; intuneconfig = $true })) -Backups @(New-Backup -Tenant 'a.com' -DaysAgo 0.5)
            $Row = (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive).Rows[0]
            $Row.cippStatus | Should -Be 'Partial'
            $Row.gapCodes | Should -Be @('NoCA', 'NoUsersGroups')
            @($Row.gapList).Count | Should -Be 2
            $Row.gapList[0] | Should -BeLike '*Conditional Access*'
        }

        It 'ignores the instance-wide CIPP configuration backup task' {
            Set-Fixture -Tasks @(New-Task -Name 'Automated CIPP Backup' -Tenant 'AllTenants' -BackupType 'CIPP')
            (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive).Rows[0].gapCodes | Should -Be @('NoTask')
        }

        It 'skips -partN rows and falls back to the RowKey for tenant and time' {
            $Stamp = [datetime]::UtcNow.AddHours(-6).ToString('yyyy-MM-dd-HHmm')
            Set-Fixture -Tasks @(New-Task -Tenant 'a.com') -Backups @(
                (New-Backup -RowKey "a.com_$Stamp" -NoTimestamp -NoTenantColumn),
                (New-Backup -Tenant 'a.com' -DaysAgo 0 -RowKey "a.com_$Stamp-part1")
            )
            $Row = (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive).Rows[0]
            $Row.cippBackupCount | Should -Be 1
            $Row.cippLastBackup | Should -Not -BeNullOrEmpty
            $Row.cippLastBackupAgeDays | Should -BeLessThan 1
            $Row.cippStatus | Should -Be 'Covered'
        }

        It 'records a storage failure as an error instead of failing the report' {
            Set-Fixture
            Mock Get-CIPPAzDataTableEntity { throw 'storage down' }
            $R = Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive
            @($R.Errors).Count | Should -Be 2
            $R.Rows[0].gapCodes | Should -Be @('NoTask')
        }

        It 'throws for a tenant CIPP does not know' {
            Set-Fixture
            { Get-CIPPEntraRecoveryCoverage -TenantFilter 'nope.com' -SkipLive } | Should -Throw '*not found*'
        }
    }

    Context 'Entra licence and native snapshots' {
        It 'makes no Graph calls with SkipLive' {
            Set-Fixture
            $Row = (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com' -SkipLive).Rows[0]
            $script:BulkCalls.Count | Should -Be 0
            $Row.nativeStatus | Should -Be 'Not checked'
            $Row.entraLicence | Should -Be 'P1'
            $Row.nativeEligible | Should -BeTrue
        }

        It 'reads snapshots and soft-deleted CA objects as app on v1.0 and summarises them' {
            $Now = [datetime]::UtcNow
            Set-Fixture -Bulk @{
                'a.com' = @{
                    snapshots = @{ status = 200; value = @(
                            [pscustomobject]@{ id = 's1'; createdDateTime = $Now.AddDays(-4.5).ToString('o'); totalChangedObjects = 10 },
                            [pscustomobject]@{ id = 's2'; createdDateTime = $Now.AddHours(-3).ToString('o'); totalChangedObjects = 7 }
                        )
                    }
                    deletedCa = @{ status = 200; value = @([pscustomobject]@{ id = 'p1'; displayName = 'Block legacy auth' }) }
                    deletedNl = @{ status = 200; value = @() }
                }
            }
            $R = Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com'
            $Row = $R.Rows[0]
            $script:BulkCalls[0].AsApp | Should -BeTrue
            $script:BulkCalls[0].Version | Should -Be 'v1.0'
            $Row.nativeStatus | Should -Be 'Available'
            $Row.nativeSnapshotCount | Should -Be 2
            $Row.nativeLatestAgeHours | Should -BeGreaterOrEqual 2.9
            $Row.nativeLatestAgeHours | Should -BeLessOrEqual 3.1
            $Row.nativeWindowDays | Should -Be 4.5
            $Row.nativeLatestChangedObjects | Should -Be 7
            $Row.softDeletedCaPolicies | Should -Be 1
            $Row.softDeletedCaPolicyNames | Should -Be 'Block legacy auth'
            $Row.softDeletedNamedLocations | Should -Be 0
            $R.Summary.NativeAvailable | Should -Be 1
            $R.Summary.SoftDeletedCaPolicies | Should -Be 1
        }

        It 'reports No permission on 403 (the CIPP app lacked EntraBackup.Read.All on 2026-11-01)' {
            Set-Fixture -Bulk @{ 'a.com' = @{ snapshots = @{ status = 403; value = @() } } }
            $R = Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com'
            $R.Rows[0].nativeStatus | Should -BeLike 'No permission*'
            $R.Summary.NativeNoPermission | Should -Be 1
        }

        It 'does not ask an unlicensed tenant for snapshots but still counts soft-deleted CA objects' {
            Set-Fixture -Caps @{ 'a.com' = @{ AAD_PREMIUM = $false; AAD_PREMIUM_P2 = $false } }
            $Row = (Get-CIPPEntraRecoveryCoverage -TenantFilter 'a.com').Rows[0]
            $Row.entraLicence | Should -Be 'None'
            $Row.nativeEligible | Should -BeFalse
            $Row.nativeStatus | Should -BeLike 'Not licensed*'
            $script:BulkCalls[0].Ids | Should -Not -Contain 'snapshots'
            $script:BulkCalls[0].Ids | Should -Contain 'deletedCa'
        }

        It 'reports P2 and an Unknown licence when the capability lookup fails' {
            Set-Fixture -Tenants @($script:TenantA, $script:TenantB) -Caps @{ 'a.com' = @{ AAD_PREMIUM = $true; AAD_PREMIUM_P2 = $true } }
            Mock Get-CIPPTenantCapabilities { if ($TenantFilter -eq 'b.com') { throw 'no token' } [pscustomobject]$script:F.Caps[$TenantFilter] }
            $R = Get-CIPPEntraRecoveryCoverage -TenantFilter 'AllTenants' -SkipLive
            ($R.Rows | Where-Object tenant -EQ 'a.com').entraLicence | Should -Be 'P2'
            ($R.Rows | Where-Object tenant -EQ 'b.com').entraLicence | Should -Be 'Unknown'
            @($R.Errors | Where-Object { $_ -like 'b.com*' }).Count | Should -Be 1
        }

        It 'keeps going when one tenant batch throws' {
            Set-Fixture -Tenants @($script:TenantA, $script:TenantB)
            Mock New-GraphBulkRequest { if ($tenantid -eq 'a.com') { throw 'batch failed' } foreach ($R in $Requests) { [pscustomobject]@{ id = $R.id; status = 200; body = [pscustomobject]@{ value = @() } } } }
            $R = Get-CIPPEntraRecoveryCoverage -TenantFilter 'AllTenants'
            ($R.Rows | Where-Object tenant -EQ 'a.com').nativeStatus | Should -Be 'Error'
            ($R.Rows | Where-Object tenant -EQ 'b.com').nativeStatus | Should -Be 'No snapshots yet'
        }
    }
}
