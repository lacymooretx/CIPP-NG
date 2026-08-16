# Group membership must RECONCILE, not just accumulate. A client that stops being managed
# has to leave the managed group, otherwise the group becomes "everyone who was ever
# managed" and the documentation keeps treating an ex-client's findings as our obligation.
#
# The other half of this: the group is derived from ConnectWise, so a hand-added member
# that ConnectWise does not agree with must be removed on the next run.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    # In-memory stand-ins for the two Azure tables.
    # Explicit globals: a helper function defined in BeforeAll does not resolve $script:
    # to the same container Pester created it in.
    $global:GroupRows = [System.Collections.Generic.List[object]]::new()
    $global:MemberRows = [System.Collections.Generic.List[object]]::new()

    # Get-CippTable returns a hashtable that callers SPLAT, so its keys arrive as parameter
    # names: @GroupTable becomes -Table 'TenantGroups'. $Table is therefore a string here,
    # not an object with a .Table property - getting that wrong made every test throw.
    function Get-CippTable { param($tablename) @{ Table = $tablename } }
    function Get-CIPPAzDataTableEntity {
        param($Table, $Filter)
        if ($Table -eq 'TenantGroups') {
            # The stub MUST honour the PartitionKey filter. The original returned every row
            # regardless, which is exactly why a group written under PartitionKey 'Group' -
            # invisible to Get-TenantGroups and therefore to the tenant selector, dynamic
            # rules and scheduled-task fan-out - passed all seven tests.
            if ($Filter -match "PartitionKey eq '([^']+)'") {
                $Pk = $Matches[1]
                return @($global:GroupRows | Where-Object { $_.PartitionKey -eq $Pk })
            }
            return @($global:GroupRows)
        }
        if ($Filter -match "GroupId eq '([^']+)'") {
            $Id = $Matches[1]
            return @($global:MemberRows | Where-Object { $_.GroupId -eq $Id })
        }
        return @($global:MemberRows)
    }
    function Add-CIPPAzDataTableEntity {
        param($Table, $Entity, [switch]$Force)
        # NOT `$List = if (...) { $rows }` - the output of an `if` goes through the
        # pipeline, which unrolls an EMPTY collection to $null. Same trap that broke the
        # continuation-field lookup in production; it bites just as hard in a test stub.
        $List = $null
        if ($Table -eq 'TenantGroups') { $List = $global:GroupRows } else { $List = $global:MemberRows }
        $Existing = $List | Where-Object { $_.RowKey -eq $Entity.RowKey } | Select-Object -First 1
        if ($Existing) { $null = $List.Remove($Existing) }
        $List.Add([pscustomobject]$Entity)
    }
    function Remove-CIPPAzDataTableEntity {
        param($Table, $Entity, [switch]$Force)
        $Existing = $global:MemberRows | Where-Object { $_.RowKey -eq $Entity.RowKey } | Select-Object -First 1
        if ($Existing) { $null = $global:MemberRows.Remove($Existing) }
    }

    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/TenantGroups/Set-CIPPTenantGroupMembership.ps1')

    function Reset-Tables {
        $global:GroupRows.Clear(); $global:MemberRows.Clear()
    }
    function Member($Id, $Label) { @{ value = $Id; label = $Label } }
    function CurrentIds($GroupName) {
        $g = $global:GroupRows | Where-Object { $_.Name -eq $GroupName } | Select-Object -First 1
        @($global:MemberRows | Where-Object { $_.GroupId -eq $g.RowKey } | ForEach-Object { $_.customerId }) | Sort-Object
    }
}

Describe 'Set-CIPPTenantGroupMembership' {
    BeforeEach { Reset-Tables }

    It 'creates the group when it does not exist' {
        $Changes = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'))
        $Changes | Should -Contain "Created group 'Managed Clients'"
        CurrentIds 'Managed Clients' | Should -Be @('a')
    }

    It 'adds a member that ConnectWise now says is managed' {
        $null = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'))
        $Changes = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'), (Member 'b' 'IMTEC'))

        $Changes | Should -Contain 'Managed Clients + IMTEC'
        CurrentIds 'Managed Clients' | Should -Be @('a', 'b')
    }

    It 'removes a member that no longer qualifies' {
        # The property that makes this a sync rather than an append-only list.
        $null = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'), (Member 'b' 'IMTEC'))
        $Changes = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'))

        $Changes | Should -Contain 'Managed Clients - b'
        CurrentIds 'Managed Clients' | Should -Be @('a')
    }

    It 'reports no changes on an unchanged run' {
        $null = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'))
        $Changes = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'))

        # A scheduled job that logs on every no-op run trains people to ignore it.
        @($Changes).Count | Should -Be 0
    }

    It 'empties a group when nothing qualifies any more' {
        $null = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'))
        $null = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @()
        CurrentIds 'Managed Clients' | Should -BeNullOrEmpty
    }

    It 'writes nothing in WhatIf mode but still reports the changes' {
        $null = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'))
        $Changes = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'), (Member 'b' 'IMTEC')) -WhatIfOnly

        $Changes | Should -Contain 'Managed Clients + IMTEC'
        CurrentIds 'Managed Clients' | Should -Be @('a')
    }

    It 'creates the group under PartitionKey TenantGroup so every consumer can see it' {
        # Regression, production bug found 2026-08-16. The group was created under
        # PartitionKey 'Group' while Get-TenantGroups.ps1 and ten other call sites filter on
        # 'TenantGroup'. The row existed, the sync reported success, and the group was
        # invisible to the tenant selector and to scheduled-task fan-out - which is the
        # mechanism that scopes alerts to managed clients only.
        $null = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'))

        $Group = $global:GroupRows | Where-Object { $_.Name -eq 'Managed Clients' } | Select-Object -First 1
        $Group.PartitionKey | Should -Be 'TenantGroup'
        $Group.GroupType | Should -Be 'static'
    }

    It 'does not adopt a group stored under the wrong PartitionKey' {
        # A legacy row from the buggy version must not be reused: adopting it would keep
        # writing members under a GroupId that resolves to nothing.
        $global:GroupRows.Add([pscustomobject]@{
                PartitionKey = 'Group'; RowKey = 'legacy-id'; Name = 'Managed Clients'
                Description = ''; GroupType = 'static'
            })

        $Changes = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'))

        $Changes | Should -Contain "Created group 'Managed Clients'"
        $Good = $global:GroupRows | Where-Object { $_.Name -eq 'Managed Clients' -and $_.PartitionKey -eq 'TenantGroup' } | Select-Object -First 1
        $Good | Should -Not -BeNullOrEmpty
        # Members land under the reachable group, not the orphan.
        @($global:MemberRows | Where-Object { $_.GroupId -eq $Good.RowKey }).Count | Should -Be 1
        @($global:MemberRows | Where-Object { $_.GroupId -eq 'legacy-id' }).Count | Should -Be 0
    }

    It 'ignores malformed members rather than writing a null customerId' {
        $Changes = Set-CIPPTenantGroupMembership -GroupName 'Managed Clients' -Members @((Member 'a' 'Acme'), @{ label = 'no id' }, $null)
        CurrentIds 'Managed Clients' | Should -Be @('a')
        $Changes | Should -Not -Contain 'Managed Clients + no id'
    }
}
