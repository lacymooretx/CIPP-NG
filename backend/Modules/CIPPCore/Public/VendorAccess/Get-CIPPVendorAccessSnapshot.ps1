function Get-CIPPVendorAccessSnapshot {
    <#
    .SYNOPSIS
        Reads the saved Vendor Access report for one tenant or all tenants from the CippVendorAccess table.
    .DESCRIPTION
        Returns @{ GeneratedAt; Tenants; Items; Summary }.
        - Items: every current item, plus items removed in the last RecentDays days (Removed = true). Each carries
          Tenant, TenantName, FirstSeen, IsNew and RemovedAt.
        - IsNew: first seen in the last RecentDays days, and not part of the tenant's first (baseline) run.
        - Summary counts current items only.
        Third party means every organisation except Aspendora's CIPP partner tenant.
        Aspendora fork addition (Vendor Access).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [string]$TenantFilter = 'AllTenants',
        [int]$RecentDays = 7
    )

    $Table = Get-CIPPTable -TableName 'CippVendorAccess'
    $Now = [datetime]::UtcNow
    $Rows = @(Get-CIPPAzDataTableEntity @Table)
    $Want = if ($TenantFilter -and $TenantFilter -ne 'AllTenants') {
        $T = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1
        @(([string]($T.defaultDomainName ?? $TenantFilter)).ToLowerInvariant())
    } else { $null }

    $Runs = @($Rows | Where-Object { $_.PartitionKey -eq 'Run' -and (-not $Want -or $_.RowKey -in $Want) })
    $RunByPk = @{}
    foreach ($R in $Runs) { $RunByPk[[string]$R.RowKey] = $R }
    $ToUtc = { param($V) if ($V) { ([datetimeoffset]$V).UtcDateTime } else { $null } }

    $Items = [System.Collections.Generic.List[object]]::new()
    foreach ($Row in $Rows) {
        if ($Row.PartitionKey -in @('Run', 'Settings', 'Weekly') -or ($Want -and $Row.PartitionKey -notin $Want)) { continue }
        $Removed = [bool]$Row.Removed
        $RemovedAt = & $ToUtc $Row.RemovedAt
        if ($Removed -and (-not $RemovedAt -or $RemovedAt -lt $Now.AddDays(-$RecentDays))) { continue }
        $Item = try { [string]$Row.Data | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        $FirstSeen = & $ToUtc $Row.FirstSeen
        $Run = $RunByPk[[string]$Row.PartitionKey]
        $Item | Add-Member -NotePropertyName Tenant -NotePropertyValue ([string]$Row.PartitionKey) -Force
        $Item | Add-Member -NotePropertyName TenantName -NotePropertyValue ([string]$Run.TenantName) -Force
        $Item | Add-Member -NotePropertyName FirstSeen -NotePropertyValue $FirstSeen -Force
        $Item | Add-Member -NotePropertyName IsNew -NotePropertyValue ((-not $Removed) -and (-not [bool]$Row.Baseline) -and $FirstSeen -and $FirstSeen -ge $Now.AddDays(-$RecentDays)) -Force
        $Item | Add-Member -NotePropertyName Removed -NotePropertyValue $Removed -Force
        $Item | Add-Member -NotePropertyName RemovedAt -NotePropertyValue $RemovedAt -Force
        $Item | Add-Member -NotePropertyName IsThirdParty -NotePropertyValue ($Item.OrganisationType -ne 'Partner tenant') -Force
        $Items.Add($Item)
    }

    $Current = @($Items | Where-Object { -not $_.Removed })
    $ThirdParty = @($Current | Where-Object IsThirdParty)
    $Tenants = foreach ($R in $Runs) {
        [pscustomobject]@{
            Tenant                  = [string]$R.RowKey
            TenantName              = [string]$R.TenantName
            GeneratedAt             = & $ToUtc $R.GeneratedAt
            FirstRunAt              = & $ToUtc $R.FirstRunAt
            Source                  = [string]$R.Source
            SignInActivityAvailable = [bool]$R.SignInActivityAvailable
            Errors                  = @(try { [string]$R.Errors | ConvertFrom-Json -ErrorAction Stop } catch { @() }) | Where-Object { $_ }
            LastError               = [string]$R.LastError
        }
    }
    $Generated = @($Tenants.GeneratedAt | Where-Object { $_ } | Sort-Object) | Select-Object -First 1

    [pscustomobject]@{
        GeneratedAt = $Generated
        Tenants     = @($Tenants | Sort-Object TenantName)
        Items       = $Items.ToArray()
        Summary     = [pscustomobject]@{
            Tenants             = @($Tenants).Count
            Items               = $Current.Count
            ThirdPartyItems     = $ThirdParty.Count
            Apps                = @($ThirdParty | Where-Object Kind -EQ 'App').Count
            AppsWithPermissions = @($ThirdParty | Where-Object { $_.Kind -eq 'App' -and $_.HasPermissions }).Count
            ForeignRoleHolders  = @($ThirdParty | Where-Object Kind -EQ 'ForeignRoleHolder').Count
            GuestRoleHolders    = @($ThirdParty | Where-Object Kind -EQ 'GuestRoleHolder').Count
            ServiceProviders    = @($ThirdParty | Where-Object Kind -EQ 'ServiceProvider').Count
            Organisations       = @($ThirdParty | ForEach-Object { if ($_.OrganisationId) { $_.OrganisationId } else { $_.Organisation } } | Where-Object { $_ } | Sort-Object -Unique).Count
            HighRisk            = @($ThirdParty | Where-Object { $_.Risk -in @('Critical', 'High') }).Count
            Critical            = @($ThirdParty | Where-Object Risk -EQ 'Critical').Count
            Stale               = @($ThirdParty | Where-Object { $_.Stale -eq $true }).Count
            SignInUnknown       = @($ThirdParty | Where-Object SignInActivity -EQ 'Unknown').Count
            New                 = @($Current | Where-Object IsNew).Count
            Removed             = @($Items | Where-Object Removed).Count
            TenantsWithErrors   = @($Tenants | Where-Object { $_.LastError -or @($_.Errors).Count -gt 0 }).Count
        }
    }
}
