function Sync-CIPPTenantGroupsFromConnectWise {
    <#
    .SYNOPSIS
        Derive CIPP tenant group membership from ConnectWise company types.
    .DESCRIPTION
        ConnectWise already knows which clients are under a managed agreement - it is the
        system the agreement lives in. Maintaining the same fact a second time by hand in
        CIPP guarantees the two drift, and they did: IMTEC Services was type 'Managed
        Client' in ConnectWise and missing from the CIPP managed group entirely, so its
        documentation reported it as unclassified.

        This makes ConnectWise the source of truth. Every tenant mapped to a ConnectWise
        company is placed in the Managed or Unmanaged group according to whether that
        company carries the managed company type, and the groups are reconciled - members
        that no longer qualify are removed, not just added.

        Deliberately does NOT exclude tenants from CIPP. A company that has gone
        Offboarding in ConnectWise is reported here for a human to action, because
        excluding a tenant stops all documentation and monitoring for it and that is not a
        decision to make from a company-status field.

    .PARAMETER ManagedTypeName
        The ConnectWise company type that means "under a managed agreement".
    .PARAMETER ManagedGroupName
        CIPP tenant group receiving managed clients. Created if missing.
    .PARAMETER UnmanagedGroupName
        CIPP tenant group receiving mapped-but-unmanaged clients. Created if missing.
    .PARAMETER WhatIfOnly
        Report the changes that would be made without writing anything.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$ManagedTypeName = 'Managed Client',
        [string]$ManagedGroupName = 'Managed Clients',
        [string]$UnmanagedGroupName = 'Unmanaged Clients',
        [switch]$WhatIfOnly
    )

    $Result = [PSCustomObject]@{
        Managed     = [System.Collections.Generic.List[string]]::new()
        Unmanaged   = [System.Collections.Generic.List[string]]::new()
        Changes     = [System.Collections.Generic.List[string]]::new()
        Unmapped    = [System.Collections.Generic.List[string]]::new()
        Offboarding = [System.Collections.Generic.List[string]]::new()
        Errors      = [System.Collections.Generic.List[string]]::new()
    }

    # ---- ConnectWise configuration -------------------------------------------------
    $ConfigTable = Get-CIPPTable -TableName Extensionsconfig
    $Configuration = ((Get-CIPPAzDataTableEntity @ConfigTable).config | ConvertFrom-Json -ErrorAction Stop).ConnectWise
    if (-not $Configuration -or $Configuration.Enabled -ne $true) {
        $Result.Errors.Add('The ConnectWise extension is not enabled; nothing to sync from.')
        return $Result
    }
    $Headers = Get-ConnectWiseHeaders -Configuration $Configuration
    $BaseURL = "$($Configuration.BaseURL)/v4_6_release/apis/3.0"

    # ---- tenant -> ConnectWise company mapping -------------------------------------
    $ExtensionMappings = @(Get-ExtensionMapping -Extension 'ConnectWise')
    if ($ExtensionMappings.Count -eq 0) {
        $Result.Errors.Add('No tenants are mapped to ConnectWise companies; nothing to sync.')
        return $Result
    }
    $Tenants = Get-Tenants -IncludeErrors

    # ---- ConnectWise companies, with their types -----------------------------------
    # Fetch whole company objects rather than a `fields=` projection. A first cut asked for
    # fields=id,name,status,types and every company came back unusable, so the sync would
    # have emptied both groups - caught by running it in WhatIf first. This is the same
    # call shape Get-ConnectWiseMapping already uses successfully.
    $Companies = @{}
    $Page = 1
    $PageSize = 1000
    do {
        $Uri = "$BaseURL/company/companies?pageSize=$PageSize&page=$Page"
        $Batch = @(Invoke-RestMethod -AllowInsecureRedirect -Uri $Uri -Method GET -Headers $Headers)
        foreach ($Company in $Batch) { $Companies["$($Company.id)"] = $Company }
        $Page++
    } while ($Batch.Count -eq $PageSize)

    if ($Companies.Count -eq 0) {
        # Never reconcile against an empty picture: that would remove every member of both
        # groups because "ConnectWise says nobody is managed".
        $Result.Errors.Add('ConnectWise returned no companies; refusing to reconcile group membership against an empty result.')
        return $Result
    }

    # ---- classify ------------------------------------------------------------------
    $ManagedMembers = [System.Collections.Generic.List[object]]::new()
    $UnmanagedMembers = [System.Collections.Generic.List[object]]::new()

    foreach ($Mapping in $ExtensionMappings) {
        $Tenant = $Tenants | Where-Object { $_.customerId -eq $Mapping.RowKey } | Select-Object -First 1
        if (-not $Tenant) { continue }

        $Company = $Companies["$($Mapping.IntegrationId)"]
        if (-not $Company) {
            $Result.Unmapped.Add("$($Tenant.displayName) -> ConnectWise company $($Mapping.IntegrationId) not found or inactive")
            continue
        }

        if ("$($Company.status.name)" -match 'Offboard|Inactive') {
            # Reported, never actioned - see the note in the description.
            $Result.Offboarding.Add("$($Tenant.displayName) -> ConnectWise status '$($Company.status.name)'")
        }

        $IsManaged = @($Company.types) | Where-Object { $_.name -eq $ManagedTypeName }
        $Member = @{ value = $Tenant.customerId; label = $Tenant.displayName }

        if ($IsManaged) {
            $ManagedMembers.Add($Member)
            $Result.Managed.Add([string]$Tenant.displayName)
        } else {
            $UnmanagedMembers.Add($Member)
            $Result.Unmanaged.Add([string]$Tenant.displayName)
        }
    }

    # ---- reconcile the two groups --------------------------------------------------
    foreach ($Pair in @(
            @{ Name = $ManagedGroupName; Members = $ManagedMembers; Description = "Clients under a managed agreement. Membership is synced from ConnectWise company type '$ManagedTypeName' - edit it there, not here." },
            @{ Name = $UnmanagedGroupName; Members = $UnmanagedMembers; Description = "Mapped to a ConnectWise company without the '$ManagedTypeName' type. Findings are informational: confirm scope before doing remediation work." }
        )) {
        try {
            $Changes = Set-CIPPTenantGroupMembership -GroupName $Pair.Name -Description $Pair.Description -Members $Pair.Members -WhatIfOnly:$WhatIfOnly
            foreach ($Change in $Changes) { $Result.Changes.Add($Change) }
        } catch {
            $Result.Errors.Add("$($Pair.Name): $($_.Exception.Message)")
        }
    }

    $Summary = "ConnectWise -> CIPP tenant groups: $($Result.Managed.Count) managed, $($Result.Unmanaged.Count) unmanaged, $($Result.Changes.Count) change(s)"
    if ($WhatIfOnly) { $Summary = "[WhatIf] $Summary" }
    Write-LogMessage -API 'TenantGroupSync' -tenant 'none' -message $Summary -sev Info

    foreach ($Note in $Result.Offboarding) {
        Write-LogMessage -API 'TenantGroupSync' -tenant 'none' -message "Offboarding in ConnectWise, still active in CIPP: $Note" -sev Warning
    }

    return $Result
}
