function Get-CIPPTenantOverviewReportData {
    <#
    .SYNOPSIS
        Gather the Tenant Overview Document model for a single tenant.
    .DESCRIPTION
        Phase 5 of the tenant documentation set, and the one a tech reaches for first: who
        this tenant is, whether we manage it, what domains it owns, what it is paying for,
        how its sharing defaults are set, and how far it has drifted from our standards.

        The management status is read from CIPP tenant groups rather than assumed. A
        tenant nobody has classified says so plainly instead of being reported as managed
        by default - documentation that quietly promotes an unmanaged client into a managed
        one is how unowned work gets started.

        Same contract as the other builders: stable section Keys for the IT Glue trait
        mapping, defensive per-section collection, and a section that could not be read is
        recorded as a note rather than rendered as an empty tenant.
    .PARAMETER TenantFilter
        Tenant default domain name.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    $GraphBeta = 'https://graph.microsoft.com/beta'
    $Findings = [System.Collections.Generic.List[object]]::new()
    $Sections = [System.Collections.Generic.List[object]]::new()
    $Notes = [System.Collections.Generic.List[object]]::new()

    function Add-Finding($Title, $Status, $Detail) {
        $Findings.Add(@{ Title = $Title; Status = $Status; Detail = $Detail })
    }
    function Add-Section($Key, $Title, $Status, $Description, $Columns, $Rows, $Empty) {
        $Sections.Add(@{ Key = $Key; Title = $Title; Status = $Status; Description = $Description; Columns = $Columns; Rows = $Rows; Empty = $Empty })
    }
    function New-RowList { , [System.Collections.Generic.List[object]]::new() }
    function Invoke-Section($Key, $Name, [scriptblock]$Builder) {
        try { & $Builder } catch {
            $Reason = $_.Exception.Message
            $Notes.Add(@{ Section = $Name; Detail = $Reason })
            $r = New-RowList; $r.Add(@($Reason))
            Add-Section $Key $Name 'warn' 'This section could not be retrieved - the data below is incomplete.' @('Error') $r 'Data unavailable.'
        }
    }

    # ---- tenant identity -----------------------------------------------------------
    $Org = $null
    try { $Org = New-GraphGetRequest -uri "$GraphBeta/organization" -tenantid $TenantFilter | Select-Object -First 1 } catch {}
    $TenantName = if ($Org.displayName) { $Org.displayName } else { $TenantFilter }
    $DefaultDomain = ($Org.verifiedDomains | Where-Object { $_.isDefault }).name
    if (-not $DefaultDomain) { $DefaultDomain = $TenantFilter }

    $State = @{ Count = 0; Managed = 'Unclassified'; UnusedLicences = 0; DriftCount = 0 }

    # ---- Tenant Details ------------------------------------------------------------
    Invoke-Section 'TenantDetails' 'Tenant Details' {
        $r = New-RowList
        $Tenant = $null
        try { $Tenant = Get-Tenants -TenantFilter $TenantFilter -IncludeErrors } catch {}

        # Management status from CIPP tenant groups. Deliberately explicit about the
        # unclassified case - see the note in the function description.
        try {
            # Get-TenantGroups returns objects with a 'Name' property, not 'GroupName' -
            # reading the wrong one silently yields an empty list, which would report every
            # tenant as Unclassified rather than erroring.
            $Groups = Get-TenantGroups -TenantFilter $TenantFilter
            $GroupNames = @($Groups | ForEach-Object { $_.Name }) | Where-Object { $_ }
            $State.Managed = if ($GroupNames -contains 'Managed Clients') { 'Managed' }
            elseif ($GroupNames -contains 'Unmanaged Clients') { 'Unmanaged' }
            else { 'Unclassified' }
            if ($GroupNames.Count -gt 0) {
                $r.Add(@('CIPP tenant groups', ($GroupNames -join ', ')))
            }
        } catch {
            $Notes.Add(@{ Section = 'Tenant Details'; Detail = "Tenant group membership unavailable: $($_.Exception.Message)" })
        }

        $r.Add(@('Management status', $State.Managed))
        $r.Add(@('Tenant name', [string]$TenantName))
        $r.Add(@('Default domain', [string]$DefaultDomain))
        if ($Tenant.customerId) { $r.Add(@('Tenant ID', [string]$Tenant.customerId)) }
        if ($Org.createdDateTime) {
            try { $r.Add(@('Tenant created', ([datetime]$Org.createdDateTime).ToString('yyyy-MM-dd'))) } catch {}
        }
        if ($Org.countryLetterCode) { $r.Add(@('Country', [string]$Org.countryLetterCode)) }
        if ($Org.onPremisesSyncEnabled -ne $null) { $r.Add(@('Directory sync (AD Connect)', "$($Org.onPremisesSyncEnabled)")) }
        if ($Tenant.delegatedPrivilegeStatus) { $r.Add(@('Delegated admin', [string]$Tenant.delegatedPrivilegeStatus)) }
        if ($Tenant.relationshipEnd) {
            try { $r.Add(@('GDAP relationship ends', ([datetime]$Tenant.relationshipEnd).ToString('yyyy-MM-dd'))) } catch {}
        }
        $TechEmails = @($Org.marketingNotificationEmails) + @($Org.technicalNotificationMails) | Where-Object { $_ }
        if ($TechEmails) { $r.Add(@('Technical notification email', ($TechEmails -join ', '))) }

        $State.Count += $r.Count
        Add-Section 'TenantDetails' 'Tenant Details' 'info' `
            'Who this tenant is, and whether we manage it.' `
            @('Property', 'Value') $r `
            'Tenant details could not be read.'
    }

    # ---- Domains -------------------------------------------------------------------
    Invoke-Section 'Domains' 'Domains' {
        $r = New-RowList
        $Domains = @($Org.verifiedDomains)
        foreach ($d in ($Domains | Sort-Object { -not $_.isDefault })) {
            $Flags = @(
                if ($d.isDefault) { 'Default' }
                if ($d.isInitial) { 'Initial' }
            ) -join ', '
            $r.Add(@([string]$d.name, [string]$d.type, ((@($d.capabilities) -join ', ')), $Flags))
        }
        $State.Count += $Domains.Count
        Add-Section 'Domains' 'Domains' 'info' `
            "$($Domains.Count) verified domains." `
            @('Domain', 'Type', 'Capabilities', 'Flags') $r `
            'No verified domains could be read.'
    }

    # ---- Licensing -----------------------------------------------------------------
    Invoke-Section 'Licensing' 'Licensing' {
        $Licences = @()
        try { $Licences = @(Get-CIPPLicenseOverview -TenantFilter $TenantFilter) } catch {
            $Notes.Add(@{ Section = 'Licensing'; Detail = "License overview unavailable: $($_.Exception.Message)" })
        }
        $r = New-RowList
        foreach ($l in ($Licences | Sort-Object License)) {
            $Used = [int]([string]$l.CountUsed -replace '[^\d-]', '')
            $Total = [int]([string]$l.TotalLicenses -replace '[^\d-]', '')
            $Avail = $Total - $Used
            if ($Avail -gt 0) { $State.UnusedLicences += $Avail }
            $Term = ''
            if ($l.TermInfo) {
                $T = @($l.TermInfo)[0]
                $Term = @(
                    if ($T.TermDuration) { [string]$T.TermDuration }
                    if ($T.NextLifecycle) {
                        try { 'renews ' + ([datetime]$T.NextLifecycle).ToString('yyyy-MM-dd') } catch {}
                    }
                    if ($T.IsTrial -eq $true) { 'TRIAL' }
                ) -join ', '
            }
            $r.Add(@([string]$l.License, "$Used", "$Total", "$Avail", $Term))
        }
        $State.Count += @($Licences).Count
        Add-Section 'Licensing' 'Licensing' 'info' `
            "$(@($Licences).Count) subscribed SKUs. 'Unused' is purchased minus assigned - licences being paid for and not used." `
            @('License', 'Assigned', 'Purchased', 'Unused', 'Term') $r `
            'No licence information could be read for this tenant.'
    }

    # ---- Sharing and Collaboration -------------------------------------------------
    Invoke-Section 'Sharing' 'Sharing and Collaboration' {
        $r = New-RowList
        $Spo = $null
        try {
            $Rows = @(Get-CIPPDbItem -TenantFilter $TenantFilter -Type 'SPOTenant' | Where-Object { $_.RowKey -notlike '*-Count' })
            foreach ($Row in $Rows) {
                if ($Row.Data) { $Spo = $Row.Data | ConvertFrom-Json -Depth 20 -ErrorAction Stop; break }
            }
        } catch {
            $Notes.Add(@{ Section = 'Sharing and Collaboration'; Detail = "SharePoint tenant settings unavailable: $($_.Exception.Message)" })
        }
        if ($Spo) {
            $r.Add(@('SharePoint external sharing', [string]$Spo.SharingCapability))
            $r.Add(@('OneDrive external sharing', [string]$Spo.ODBSharingCapability))
            if ($null -ne $Spo.DefaultSharingLinkType) { $r.Add(@('Default sharing link type', [string]$Spo.DefaultSharingLinkType)) }
            if ($null -ne $Spo.DefaultLinkPermission) { $r.Add(@('Default link permission', [string]$Spo.DefaultLinkPermission)) }
            if ($null -ne $Spo.RequireAnonymousLinksExpireInDays) { $r.Add(@('Anonymous links expire (days)', "$($Spo.RequireAnonymousLinksExpireInDays)")) }
            if ($null -ne $Spo.PreventExternalUsersFromResharing) { $r.Add(@('External users can reshare', "$(-not $Spo.PreventExternalUsersFromResharing)")) }
            if ($null -ne $Spo.OneDriveStorageQuota) { $r.Add(@('OneDrive storage quota (MB)', "$($Spo.OneDriveStorageQuota)")) }
        }
        $State.Count += $r.Count
        Add-Section 'Sharing' 'Sharing and Collaboration' 'info' `
            'Tenant-wide SharePoint and OneDrive sharing defaults.' `
            @('Setting', 'Value') $r `
            'SharePoint tenant settings are not cached for this tenant yet.'
    }

    # ---- Standards Alignment -------------------------------------------------------
    # What we said we would configure versus what is actually configured.
    Invoke-Section 'StandardsAlignment' 'Standards Alignment' {
        $r = New-RowList
        $Drift = $null
        try { $Drift = Get-CIPPDrift -TenantFilter $TenantFilter } catch {
            $Notes.Add(@{ Section = 'Standards Alignment'; Detail = "Standards drift unavailable: $($_.Exception.Message)" })
        }
        foreach ($d in @($Drift)) {
            foreach ($Dev in @($d.currentDeviations)) {
                $r.Add(@(
                        [string]($d.templateName ?? $d.standardName),
                        [string]($Dev.standardDisplayName ?? $Dev.standardName),
                        [string]$Dev.status,
                        (([string]$Dev.receivedValue) -replace '\s+', ' ')
                    ))
                $State.DriftCount++
            }
        }
        $State.Count += $State.DriftCount
        Add-Section 'StandardsAlignment' 'Standards Alignment' $(if ($State.DriftCount -gt 0) { 'warn' } else { 'info' }) `
            "$($State.DriftCount) deviations from the standards templates applied to this tenant." `
            @('Template', 'Standard', 'Status', 'Current value') $r `
            'No standards deviations. This tenant matches the templates applied to it.'
    }

    # ---- executive findings --------------------------------------------------------
    Add-Finding 'Management status' $(if ($State.Managed -eq 'Managed') { 'pass' } elseif ($State.Managed -eq 'Unmanaged') { 'info' } else { 'warn' }) `
    $(switch ($State.Managed) {
            'Managed' { 'This tenant is in the Managed Clients group. Findings here are our responsibility to remediate.' }
            'Unmanaged' { 'This tenant is in the Unmanaged Clients group. Findings are informational - confirm scope before doing remediation work.' }
            default { 'This tenant is in neither the Managed nor the Unmanaged Clients group. Classify it so findings are handled correctly.' }
        })

    if ($State.UnusedLicences -gt 0) {
        Add-Finding 'Unused licences' 'warn' "$($State.UnusedLicences) purchased licence(s) are not assigned to anyone. Worth reconciling against the agreement."
    } else {
        Add-Finding 'Unused licences' 'pass' 'Every purchased licence is assigned.'
    }

    if ($State.DriftCount -gt 0) {
        Add-Finding 'Standards drift' 'warn' "$($State.DriftCount) deviation(s) from the standards templates applied to this tenant."
    }

    Add-Finding 'Objects documented' 'info' "$($State.Count) tenant and licensing objects captured for $TenantName."

    if ($Notes.Count -gt 0) {
        Add-Finding 'Collection warnings' 'warn' "$($Notes.Count) section(s) could not be read in full. See collection notes."
    }

    return @{
        Title           = 'Tenant Overview Document'
        TenantName      = $TenantName
        TenantDomain    = $DefaultDomain
        GeneratedDate   = (Get-Date).ToString('dd MMMM yyyy')
        Findings        = $Findings
        Sections        = $Sections
        CollectionNotes = $Notes
        ObjectCount     = $State.Count
    }
}
