function Get-CIPPEntraRecoveryCoverage {
    <#
    .SYNOPSIS
        Per tenant: Microsoft Entra Backup and Recovery snapshot status, CIPP's own scheduled backup coverage, and the
        soft-deleted Conditional Access objects that can still be restored.
    .DESCRIPTION
        Read only. Shared by ListEntraRecoveryCoverage (the Entra Recovery Coverage page) and the BackupCoverage alert.

        Native (Microsoft Entra Backup and Recovery), verified 2026-11-01:
          GET v1.0 directory/recovery/snapshots (also in beta). One snapshot a day, kept 5 days per the Graph docs
          (7 per the Entra overview page, updated later). Needs Entra ID P1 or P2 (Business Premium includes P1) and the
          EntraBackup.Read.All permission. The CIPP SAM app did not hold that permission on 2026-11-01 (403 as app,
          401 delegated), so the status reads 'No permission' until it is added and consented. Hard-deleted objects
          are never recoverable from it.

        CIPP backup: the ScheduledTasks rows that run New-CIPPBackup with backupType Scheduled, resolved to tenants the
        way the scheduler fans them out (direct tenant, AllTenants, stored selection or tenant group, minus exclusions),
        and the ScheduledBackup rows those runs wrote. Components come from the task's ScheduledBackupValues; the latest
        backup's ItemCounts (written by the CIPP-23 integrity manifest) show what was actually captured.
        CIPP backup components do NOT include authentication-method policies, app registrations, service principals
        or named locations that no CA policy references. 'ca' captures each CA policy plus the named locations it
        references (LocationInfo).

        Soft-deleted CA policies and named locations (v1.0 identity/conditionalAccess/deletedItems) are counted: they
        are restorable for 30 days but are NOT in directory/deletedItems, so CIPP's Deleted Items page does not list them.
        Aspendora fork addition (Vikunja CIPP-17).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        # A daily backup that has not run for this many days counts as stale.
        [int]$MaxBackupAgeDays = 2,
        # Skip the per-tenant Graph calls (snapshots, soft-deleted CA objects). Licence and CIPP coverage still run.
        [switch]$SkipLive
    )

    $Now = [datetime]::UtcNow
    $Errors = [System.Collections.Generic.List[string]]::new()

    function ConvertTo-UtcDate($Value) {
        if ($null -eq $Value -or "$Value" -eq '') { return $null }
        try {
            if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
            if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
            return ([datetimeoffset]::Parse([string]$Value, [cultureinfo]::InvariantCulture)).UtcDateTime
        } catch { return $null }
    }
    function Test-Enabled($Value) { return ($Value -eq $true -or "$Value" -eq 'true') }
    # The leading comma matters: returning an empty HashSet unrolls it to $null.
    function New-NameSet { , [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }

    # --- Tenants in scope ---------------------------------------------------------------------------------------
    # Wrapped in @() outside the if: an if-expression unrolls a one-element array.
    $Tenants = @(if ($TenantFilter -eq 'AllTenants') { Get-Tenants } else { Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1 })
    if ($Tenants.Count -eq 0) { throw "Tenant $TenantFilter was not found in CIPP." }

    # --- CIPP scheduled backup tasks, with their tenant scope resolved once --------------------------------------
    $TaskScopes = [System.Collections.Generic.List[object]]::new()
    try {
        $TaskTable = Get-CIPPTable -TableName 'ScheduledTasks'
        $Tasks = @(Get-CIPPAzDataTableEntity @TaskTable -Filter "PartitionKey eq 'ScheduledTask' and Command eq 'New-CIPPBackup'")
    } catch {
        $Tasks = @()
        $Errors.Add("Scheduled backup tasks could not be read: $((Get-CippException -Exception $_).NormalizedError)")
    }
    foreach ($Task in $Tasks) {
        $Params = $null
        try { $Params = $Task.Parameters | ConvertFrom-Json -ErrorAction Stop } catch { $Params = $null }
        # backupType CIPP is the instance-wide configuration backup on the partner tenant, not a tenant backup.
        if ([string]$Params.backupType -ne 'Scheduled') { continue }

        $Components = New-NameSet
        if ($Params.ScheduledBackupValues) {
            foreach ($Prop in $Params.ScheduledBackupValues.PSObject.Properties) {
                if (Test-Enabled $Prop.Value) { $null = $Components.Add([string]$Prop.Name) }
            }
        }

        # Mirrors Start-UserTasksOrchestrator: a stored selection is only trusted on an AllTenants row, otherwise a
        # tenant group, otherwise the AllTenants sentinel, otherwise the single tenant on the row.
        $All = $false
        $Members = New-NameSet
        $Excluded = New-NameSet
        $ScopeKnown = $true
        try {
            $UsesStoredSelection = $Task.Tenants -and $Task.Tenant -eq 'AllTenants'
            $Selection = if ($UsesStoredSelection) { @($Task.Tenants | ConvertFrom-Json -ErrorAction Stop) } elseif ($Task.TenantGroup) { @($Task.TenantGroup | ConvertFrom-Json -ErrorAction Stop) } else { $null }
            if ($Selection) {
                $Expanded = @(Expand-CIPPTenantGroups -TenantFilter $Selection)
                $Values = @($Expanded | ForEach-Object { [string]$_.value } | Where-Object { $_ })
                if ($Values -contains 'AllTenants') { $All = $true } else { foreach ($V in $Values) { $null = $Members.Add($V) } }
            } elseif ($Task.Tenant -eq 'AllTenants') {
                $All = $true
            } elseif ($Task.Tenant) {
                $null = $Members.Add([string]$Task.Tenant)
            }
            # Legacy snapshot exclusions are ignored by the scheduler, so they are ignored here too.
            $IsLegacySnapshot = $UsesStoredSelection -and -not $Task.TenantSelectionVersion -and -not $All
            if ($Task.excludedTenants -and -not $IsLegacySnapshot) {
                foreach ($E in ([string]$Task.excludedTenants -split ',')) { if ($E.Trim()) { $null = $Excluded.Add($E.Trim()) } }
            }
            if ($Task.excludedTenantGroups) {
                $ExcludedGroups = $Task.excludedTenantGroups | ConvertFrom-Json -ErrorAction Stop
                if ($ExcludedGroups) {
                    foreach ($E in @(Expand-CIPPTenantGroups -TenantFilter $ExcludedGroups)) { if ($E.value) { $null = $Excluded.Add([string]$E.value) } }
                }
            }
        } catch {
            $ScopeKnown = $false
            $Errors.Add("Could not resolve the tenants of backup task '$($Task.Name)': $((Get-CippException -Exception $_).NormalizedError)")
        }

        $TaskScopes.Add([pscustomobject]@{
                Name         = [string]$Task.Name
                All          = $All
                Members      = $Members
                Excluded     = $Excluded
                ScopeKnown   = $ScopeKnown
                Components   = $Components
                Disabled     = ($Task.Disabled -eq $true)
                TaskState    = [string]$Task.TaskState
                Recurrence   = [string]$Task.Recurrence
            })
    }

    # --- Backups actually written (row metadata only; the payload stays in blob storage) -------------------------
    $BackupsByTenant = @{}
    try {
        $BackupTable = Get-CIPPTable -TableName 'ScheduledBackup'
        $BackupTable.Property = @('PartitionKey', 'RowKey', 'Timestamp', 'TenantFilter', 'ItemCounts')
        $BackupRows = @(Get-CIPPAzDataTableEntity @BackupTable -Filter "PartitionKey eq 'ScheduledBackup'")
    } catch {
        $BackupRows = @()
        $Errors.Add("Backup history could not be read: $((Get-CippException -Exception $_).NormalizedError)")
    }
    foreach ($Row in $BackupRows) {
        $RowKey = [string]$Row.RowKey
        # Oversized legacy rows are split into -partN rows; only the head row is a backup.
        if ($RowKey -like '*-part*' -and ($RowKey -replace '-part[0-9]+$', '') -ne $RowKey) { continue }
        $Owner = if ($Row.TenantFilter) { [string]$Row.TenantFilter } else { $RowKey -replace '_[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}$', '' }
        $Key = $Owner.ToLowerInvariant()
        if (-not $BackupsByTenant.ContainsKey($Key)) { $BackupsByTenant[$Key] = [System.Collections.Generic.List[object]]::new() }
        $BackupsByTenant[$Key].Add($Row)
    }

    # --- Per tenant ------------------------------------------------------------------------------------------------
    $Rows = foreach ($Tenant in $Tenants) {
        $Domain = [string]$Tenant.defaultDomainName
        # Lower-cased and unique: a tenant whose default domain is its initial domain must not count each backup twice.
        $Ids = @(@($Tenant.defaultDomainName, $Tenant.initialDomainName, $Tenant.customerId) | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Select-Object -Unique)

        # CIPP coverage
        $Covering = @(foreach ($Scope in $TaskScopes) {
                $InScope = $Scope.All -or @($Ids | Where-Object { $Scope.Members.Contains($_) }).Count -gt 0
                $Out = @($Ids | Where-Object { $Scope.Excluded.Contains($_) }).Count -gt 0
                if ($InScope -and -not $Out) { $Scope }
            })
        $Active = @($Covering | Where-Object { -not $_.Disabled })
        $Components = New-NameSet
        foreach ($Scope in $Active) { foreach ($C in $Scope.Components) { $null = $Components.Add($C) } }

        $TenantBackups = [System.Collections.Generic.List[object]]::new()
        foreach ($Id in $Ids) {
            $K = $Id.ToLowerInvariant()
            if ($BackupsByTenant.ContainsKey($K)) { foreach ($B in $BackupsByTenant[$K]) { $TenantBackups.Add($B) } }
        }
        $Latest = $null
        $LatestTime = $null
        foreach ($B in $TenantBackups) {
            $When = ConvertTo-UtcDate $B.Timestamp
            if (-not $When) {
                # RowKey ends with the run time (server clock, UTC on Azure).
                $Stamp = ([string]$B.RowKey) -replace '^.*_(?=[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}$)', ''
                try { $When = [datetime]::ParseExact($Stamp, 'yyyy-MM-dd-HHmm', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal') } catch { $When = $null }
            }
            if ($When -and (-not $LatestTime -or $When -gt $LatestTime)) { $LatestTime = $When; $Latest = $B }
        }
        $AgeDays = if ($LatestTime) { [math]::Round(($Now - $LatestTime).TotalDays, 1) } else { $null }
        $ItemCounts = $null
        if ($Latest -and $Latest.ItemCounts) {
            try {
                $Parsed = $Latest.ItemCounts | ConvertFrom-Json -AsHashtable -ErrorAction Stop
                $ItemCounts = (@($Parsed.Keys | Sort-Object | ForEach-Object { "$($_): $($Parsed[$_])" }) -join ', ')
            } catch { $ItemCounts = $null }
        }

        # Codes are stable (the alert keys on them); messages carry the detail.
        $Gaps = [System.Collections.Generic.List[string]]::new()
        $GapCodes = [System.Collections.Generic.List[string]]::new()
        $Severe = $false
        if ($Covering.Count -eq 0) {
            $Gaps.Add('No scheduled CIPP backup'); $GapCodes.Add('NoTask'); $Severe = $true
        } elseif ($Active.Count -eq 0) {
            $Gaps.Add('CIPP backup task is disabled'); $GapCodes.Add('TaskDisabled'); $Severe = $true
        }
        if ($Covering.Count -gt 0) {
            if (-not $LatestTime) {
                $Gaps.Add('No CIPP backup has been taken yet'); $GapCodes.Add('NoBackup'); $Severe = $true
            } elseif ($AgeDays -gt $MaxBackupAgeDays) {
                $Gaps.Add("Last CIPP backup is $AgeDays days old"); $GapCodes.Add('Stale'); $Severe = $true
            }
            if ($Active.Count -gt 0 -and -not $Components.Contains('ca')) { $Gaps.Add('Conditional Access (with its named locations) not in the backup'); $GapCodes.Add('NoCA') }
            if ($Active.Count -gt 0 -and -not ($Components.Contains('users') -and $Components.Contains('groups'))) { $Gaps.Add('Users or groups not in the backup'); $GapCodes.Add('NoUsersGroups') }
        }
        $CippStatus = if ($Severe) { 'Gap' } elseif ($Gaps.Count -gt 0) { 'Partial' } else { 'Covered' }

        # Licence: Entra Backup and Recovery needs Entra ID P1 or P2.
        $Licence = 'Unknown'
        try {
            $Caps = Get-CIPPTenantCapabilities -TenantFilter $Domain
            $Licence = if ($Caps.AAD_PREMIUM_P2 -eq $true) { 'P2' } elseif ($Caps.AAD_PREMIUM -eq $true) { 'P1' } else { 'None' }
        } catch {
            $Errors.Add("$($Domain): licence lookup failed: $((Get-CippException -Exception $_).NormalizedError)")
        }

        # Native snapshots and soft-deleted CA objects, one batch per tenant.
        $NativeStatus = 'Not checked'
        $SnapshotCount = $null
        $LatestSnapshot = $null
        $OldestSnapshot = $null
        $SnapshotChanged = $null
        $DeletedCa = $null
        $DeletedNl = $null
        $DeletedCaNames = $null
        if (-not $SkipLive) {
            $Requests = @(
                @{ id = 'snapshots'; method = 'GET'; url = 'directory/recovery/snapshots?$select=id,createdDateTime,totalChangedObjects' }
                @{ id = 'deletedCa'; method = 'GET'; url = 'identity/conditionalAccess/deletedItems/policies?$select=id,displayName,deletedDateTime' }
                @{ id = 'deletedNl'; method = 'GET'; url = 'identity/conditionalAccess/deletedItems/namedLocations?$select=id,displayName,deletedDateTime' }
            )
            # Unlicensed tenants are not asked for snapshots: the answer is known and the call only adds noise.
            if ($Licence -eq 'None') { $Requests = @($Requests | Where-Object { $_.id -ne 'snapshots' }); $NativeStatus = 'Not licensed (needs Entra ID P1/P2)' }
            try {
                $Responses = @(New-GraphBulkRequest -Requests $Requests -tenantid $Domain -asapp $true -Version 'v1.0')
                foreach ($Response in $Responses) {
                    $Status = [int]$Response.status
                    $Value = @($Response.body.value | Where-Object { $_ })
                    switch ([string]$Response.id) {
                        'snapshots' {
                            if ($Status -eq 200) {
                                $SnapshotCount = $Value.Count
                                $Times = @($Value | ForEach-Object { ConvertTo-UtcDate $_.createdDateTime } | Where-Object { $_ } | Sort-Object)
                                if ($Times.Count -gt 0) {
                                    $OldestSnapshot = $Times[0]
                                    $LatestSnapshot = $Times[-1]
                                    $NewestRow = $Value | Where-Object { (ConvertTo-UtcDate $_.createdDateTime) -eq $LatestSnapshot } | Select-Object -First 1
                                    $SnapshotChanged = $NewestRow.totalChangedObjects
                                    $NativeStatus = 'Available'
                                } else {
                                    $NativeStatus = 'No snapshots yet'
                                }
                            } elseif ($Status -in 401, 403) {
                                $NativeStatus = 'No permission (EntraBackup.Read.All)'
                            } elseif ($Status -eq 404) {
                                $NativeStatus = 'Not available in this tenant'
                            } else {
                                $NativeStatus = "Error (HTTP $Status)"
                            }
                        }
                        'deletedCa' {
                            if ($Status -eq 200) {
                                $DeletedCa = $Value.Count
                                $DeletedCaNames = (@($Value | ForEach-Object { [string]$_.displayName }) -join ', ')
                            }
                        }
                        'deletedNl' { if ($Status -eq 200) { $DeletedNl = $Value.Count } }
                    }
                }
            } catch {
                $NativeStatus = 'Error'
                $Errors.Add("$($Domain): live read failed: $((Get-CippException -Exception $_).NormalizedError)")
            }
        }

        [pscustomobject]@{
            tenant                     = $Domain
            displayName                = [string]$Tenant.displayName
            entraLicence               = $Licence
            nativeEligible             = ($Licence -in @('P1', 'P2'))
            nativeStatus               = $NativeStatus
            nativeSnapshotCount        = $SnapshotCount
            # ISO string, not the DateTime: the HTTP layer serialises a raw DateTime as an object of its parts.
            nativeLatestSnapshot       = if ($LatestSnapshot) { $LatestSnapshot.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
            nativeLatestAgeHours       = if ($LatestSnapshot) { [math]::Round(($Now - $LatestSnapshot).TotalHours, 1) } else { $null }
            nativeWindowDays           = if ($OldestSnapshot) { [math]::Round(($Now - $OldestSnapshot).TotalDays, 1) } else { $null }
            nativeLatestChangedObjects = $SnapshotChanged
            cippStatus                 = $CippStatus
            cippTasks                  = (@($Covering | ForEach-Object { if ($_.Disabled) { "$($_.Name) (disabled)" } else { $_.Name } }) -join ', ')
            cippComponents             = (@($Components | Sort-Object) -join ', ')
            cippBackupCount            = $TenantBackups.Count
            cippLastBackup             = if ($LatestTime) { ([datetime]$LatestTime).ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
            cippLastBackupAgeDays      = $AgeDays
            cippLastBackupItems        = $ItemCounts
            gaps                       = ($Gaps -join '; ')
            gapCodes                   = $GapCodes.ToArray()
            gapList                    = $Gaps.ToArray()
            softDeletedCaPolicies      = $DeletedCa
            softDeletedCaPolicyNames   = $DeletedCaNames
            softDeletedNamedLocations  = $DeletedNl
        }
    }
    $Rows = @($Rows)

    $Summary = [ordered]@{
        Tenants                = $Rows.Count
        CippCovered            = @($Rows | Where-Object cippStatus -EQ 'Covered').Count
        CippPartial            = @($Rows | Where-Object cippStatus -EQ 'Partial').Count
        CippGap                = @($Rows | Where-Object cippStatus -EQ 'Gap').Count
        NativeEligible         = @($Rows | Where-Object nativeEligible).Count
        NativeAvailable        = @($Rows | Where-Object nativeStatus -EQ 'Available').Count
        NativeNoPermission     = @($Rows | Where-Object { [string]$_.nativeStatus -like 'No permission*' }).Count
        NativeNotLicensed      = @($Rows | Where-Object { [string]$_.entraLicence -eq 'None' }).Count
        SoftDeletedCaPolicies  = [int](@($Rows | ForEach-Object { [int]$_.softDeletedCaPolicies }) | Measure-Object -Sum).Sum
        SoftDeletedNamedLocations = [int](@($Rows | ForEach-Object { [int]$_.softDeletedNamedLocations }) | Measure-Object -Sum).Sum
    }

    return [pscustomobject]@{
        Tenant           = $TenantFilter
        MaxBackupAgeDays = $MaxBackupAgeDays
        GeneratedUtc     = $Now.ToString('o')
        Summary          = $Summary
        Rows             = $Rows
        KnownLimits      = @(
            'CIPP tenant backups have no component for authentication-method policies, app registrations, service principals or unreferenced named locations.'
            'Entra Backup and Recovery keeps about 5 days of daily snapshots and cannot recover hard-deleted objects.'
            'Soft-deleted users, groups, apps and service principals are restorable for 30 days from Deleted Items; soft-deleted CA policies and named locations only from the Entra portal or Graph.'
        )
        Errors           = @($Errors)
    }
}
