function Set-CIPPTenantGroupMembership {
    <#
    .SYNOPSIS
        Reconcile a static tenant group's membership to exactly the supplied set.
    .DESCRIPTION
        Creates the group if it does not exist, adds members that should be there and
        removes members that should not. Reconciling rather than only adding is the point:
        a client that stops being managed has to leave the managed group, or the group
        becomes a list of everyone who was ever managed.

        Returns a list of human-readable changes. An unchanged group returns nothing, so a
        scheduled caller can stay quiet on a no-op run.
    .PARAMETER GroupName
        Group to reconcile. Matched by name; created with this name if absent.
    .PARAMETER Members
        The complete desired membership: @( @{ value = <customerId>; label = <displayName> } ).
    .PARAMETER WhatIfOnly
        Report the changes without writing them.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$GroupName,
        [string]$Description,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]$Members,
        [switch]$WhatIfOnly
    )

    $Changes = [System.Collections.Generic.List[string]]::new()
    $GroupTable = Get-CippTable -tablename 'TenantGroups'
    $MembersTable = Get-CippTable -tablename 'TenantGroupMembers'

    # PartitionKey must be 'TenantGroup'. Get-TenantGroups, Expand-CIPPTenantGroups, the tenant
    # selector, dynamic rules and scheduled-task fan-out all filter on it; a group written under
    # any other partition exists in the table but is invisible to every consumer, and the members
    # under it resolve to nothing. Filter the lookup on it too, so a miss creates a usable group
    # rather than silently adopting an unreachable one.
    $Group = Get-CIPPAzDataTableEntity @GroupTable -Filter "PartitionKey eq 'TenantGroup'" | Where-Object { $_.Name -eq $GroupName } | Select-Object -First 1
    if (-not $Group) {
        $GroupId = [guid]::NewGuid().ToString()
        if (-not $WhatIfOnly) {
            Add-CIPPAzDataTableEntity @GroupTable -Entity @{
                PartitionKey = 'TenantGroup'
                RowKey       = $GroupId
                Name         = $GroupName
                Description  = [string]$Description
                GroupType    = 'static'
            } -Force
        }
        $Changes.Add("Created group '$GroupName'")
    } else {
        $GroupId = $Group.RowKey
        if ($Description -and $Group.Description -ne $Description -and -not $WhatIfOnly) {
            $Group.Description = $Description
            Add-CIPPAzDataTableEntity @GroupTable -Entity $Group -Force
        }
    }

    $Desired = @($Members | Where-Object { $_ -and $_.value })
    $DesiredIds = @($Desired | ForEach-Object { [string]$_.value })
    $Current = @(Get-CIPPAzDataTableEntity @MembersTable -Filter "PartitionKey eq 'Member' and GroupId eq '$GroupId'")
    $CurrentIds = @($Current | ForEach-Object { [string]$_.customerId })

    foreach ($Member in $Desired) {
        if ($CurrentIds -contains [string]$Member.value) { continue }
        if (-not $WhatIfOnly) {
            Add-CIPPAzDataTableEntity @MembersTable -Entity @{
                PartitionKey = 'Member'
                RowKey       = '{0}-{1}' -f $GroupId, $Member.value
                GroupId      = $GroupId
                customerId   = [string]$Member.value
            } -Force
        }
        $Changes.Add("$GroupName + $($Member.label)")
    }

    foreach ($Existing in $Current) {
        if ($DesiredIds -contains [string]$Existing.customerId) { continue }
        if (-not $WhatIfOnly) {
            Remove-CIPPAzDataTableEntity @MembersTable -Entity $Existing -Force
        }
        $Changes.Add("$GroupName - $($Existing.customerId)")
    }

    return $Changes
}
