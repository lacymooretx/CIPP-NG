function Get-CIPPMessageCenterDigest {
    <#
    .SYNOPSIS
        Deduplicated, classified Message Center digest for one tenant or every managed tenant.
    .DESCRIPTION
        Read only. Shared by ListMessageCenterDigest (Tenant > Reports > Message Center Digest) and the
        MessageCenterDigest alert.

        Source: the CIPP reporting database (cache type MessageCenterMessages, written nightly by
        Set-CIPPDBCacheMessageCenterMessages from Graph v1.0 admin/serviceAnnouncement/messages, the same call
        ListMessageCenterMessages makes). AllTenants reads the cache only, since the same ~650 posts would otherwise be
        fetched live from every tenant; managed tenants with no cached posts are listed in Summary.NotCached. A single
        tenant with nothing cached is read live from Graph instead.

        Microsoft posts the same message to every tenant it applies to, so posts are deduplicated by id (MC number),
        keeping the most recently modified copy and the list of tenants that received it.

        A post is in the digest when it was published or updated within Days (default 7), when its deadline falls
        within DeadlineDays (default 30, not yet past), or, with -IncludeOpenDeadlines, whenever its deadline is still
        ahead. WindowReason says which. Informational posts are dropped unless -IncludeInformational.
        Classification is Get-CIPPMessageCenterClassification. Aspendora fork addition (Vikunja CIPP-37).
    .PARAMETER TenantFilter
        A tenant domain, or AllTenants.
    .PARAMETER MessagesByTenant
        Tenant -> posts, bypassing the cache and Graph. Used by tests.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [int]$Days = 7,
        [int]$DeadlineDays = 30,
        [switch]$IncludeInformational,
        [switch]$IncludeOpenDeadlines,
        [System.Collections.IDictionary]$MessagesByTenant,
        [datetime]$Now = [datetime]::UtcNow
    )

    $NowUtc = if ($Now.Kind -eq [System.DateTimeKind]::Local) { $Now.ToUniversalTime() } else { [datetime]::SpecifyKind($Now, [System.DateTimeKind]::Utc) }
    $WindowStart = $NowUtc.AddDays(-$Days)
    $AllTenants = $TenantFilter -eq 'AllTenants'
    $Errors = [System.Collections.Generic.List[string]]::new()
    $NotCached = @()
    $Source = 'Supplied'
    $CacheTimes = [System.Collections.Generic.List[datetime]]::new()

    $ToUtc = {
        param($Value)
        if ($null -eq $Value -or [string]$Value -eq '') { return $null }
        try {
            if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
            if ($Value -is [datetime]) {
                if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
                return $Value.ToUniversalTime()
            }
            return [datetimeoffset]::Parse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
        } catch { return $null }
    }
    $ParseRow = {
        param($Json)
        # CippJson is what ListMessageCenterMessages uses; ConvertFrom-Json is the fallback when the type is not loaded.
        if ('CIPP.CippJson' -as [type]) { return [CIPP.CippJson]::ConvertFromJson([string]$Json, $null) }
        return ([string]$Json | ConvertFrom-Json -Depth 20)
    }

    if ($null -eq $MessagesByTenant) {
        $MessagesByTenant = [ordered]@{}
        $DbTenant = if ($AllTenants) { 'allTenants' } else { $TenantFilter }
        $RowsByTenant = Get-CIPPDbItem -TenantFilter $DbTenant -Type 'MessageCenterMessages' -ByTenant
        foreach ($Tenant in @($RowsByTenant.Keys)) {
            $List = [System.Collections.Generic.List[object]]::new()
            foreach ($Row in @($RowsByTenant[$Tenant])) {
                $Parsed = try { & $ParseRow $Row.Data } catch { $null }
                foreach ($Record in @($Parsed)) { if ($Record) { $List.Add($Record) } }
                $Stamp = & $ToUtc $Row.Timestamp
                if ($Stamp) { $CacheTimes.Add($Stamp) }
            }
            if ($List.Count -gt 0) { $MessagesByTenant[[string]$Tenant] = $List }
        }
        $Source = 'Cache'

        if ($AllTenants) {
            $Managed = @(Get-Tenants | ForEach-Object { [string]$_.defaultDomainName } | Where-Object { $_ })
            $NotCached = @($Managed | Where-Object { -not $MessagesByTenant.Contains($_) } | Sort-Object)
            if ($MessagesByTenant.Count -eq 0) {
                throw 'No Message Center posts are cached for any tenant yet. Run the MessageCenterMessages cache sync (CIPP DB cache) first.'
            }
        } elseif ($MessagesByTenant.Count -eq 0) {
            $Live = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/messages' -tenantid $TenantFilter)
            $MessagesByTenant[$TenantFilter] = $Live
            $Source = 'Live'
        }
    }

    # Dedupe by MC id across tenants.
    $ById = [ordered]@{}
    foreach ($Tenant in @($MessagesByTenant.Keys)) {
        foreach ($Record in @($MessagesByTenant[$Tenant])) {
            if ($null -eq $Record -or [string]::IsNullOrWhiteSpace([string]$Record.id)) { continue }
            $Id = [string]$Record.id
            $Modified = & $ToUtc $Record.lastModifiedDateTime
            $Entry = $ById[$Id]
            if (-not $Entry) {
                $Entry = @{ Record = $Record; Modified = $Modified; Tenants = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
                $ById[$Id] = $Entry
            } elseif ($Modified -and (-not $Entry.Modified -or $Modified -gt $Entry.Modified)) {
                $Entry.Record = $Record
                $Entry.Modified = $Modified
            }
            [void]$Entry.Tenants.Add([string]$Tenant)
        }
    }

    $Items = [System.Collections.Generic.List[object]]::new()
    foreach ($Id in @($ById.Keys)) {
        $Entry = $ById[$Id]
        $M = $Entry.Record
        $Class = Get-CIPPMessageCenterClassification -Message $M -DeadlineDays $DeadlineDays -Now $NowUtc
        if (-not $IncludeInformational -and $Class.Category -eq 'Informational') { continue }

        $Start = & $ToUtc $M.startDateTime
        $Modified = $Entry.Modified
        $WindowReason = if ($Start -and $Start -ge $WindowStart) { 'New' }
        elseif ($Modified -and $Modified -ge $WindowStart) { 'Updated' }
        elseif ($Class.DueSoon) { 'Deadline approaching' }
        elseif ($IncludeOpenDeadlines -and $null -ne $Class.DaysLeft -and $Class.DaysLeft -ge 0) { 'Open deadline' }
        else { $null }
        if (-not $WindowReason) { continue }

        $Tenants = [string[]]@($Entry.Tenants)
        $Items.Add([pscustomobject]@{
                MessageId         = $Id
                Title             = [string]$M.title
                Category          = $Class.Category
                CategoryLabel     = $Class.CategoryLabel
                Notify            = $Class.Notify
                Flags             = ($Class.Flags -join ', ')
                Reasons           = ($Class.Reasons -join '; ')
                Deadline          = $Class.Deadline
                DaysLeft          = $Class.DaysLeft
                DeadlineStatus    = $Class.DeadlineStatus
                DueSoon           = $Class.DueSoon
                WindowReason      = $WindowReason
                Tenants           = $Tenants
                TenantCount       = $Tenants.Count
                TenantsText       = ($Tenants -join ', ')
                Services          = (@($M.services) -join ', ')
                Tags              = (@($M.tags) -join ', ')
                MicrosoftCategory = [string]$M.category
                Severity          = [string]$M.severity
                IsMajorChange     = [bool]$M.isMajorChange
                Published         = Format-CIPPCentralTime -Value $Start
                LastUpdated       = Format-CIPPCentralTime -Value $Modified
                PublishedUtc      = if ($Start) { $Start.ToString('o') } else { '' }
                LastUpdatedUtc    = if ($Modified) { $Modified.ToString('o') } else { '' }
                Summary           = $Class.Summary
                Link              = "https://admin.microsoft.com/#/MessageCenter/:/messages/$Id"
            })
    }

    # Alerting categories first, then the nearest deadline, then the most recently updated.
    $Sorted = @($Items | Sort-Object -Property @(
            @{ Expression = { [int]$_.Notify }; Descending = $true }
            @{ Expression = { if ($null -eq $_.DaysLeft) { [int]::MaxValue } else { [int]$_.DaysLeft } }; Descending = $false }
            @{ Expression = { $_.LastUpdatedUtc }; Descending = $true }
        ))

    $ByCategory = [ordered]@{}
    foreach ($Name in 'ActionRequired', 'Retirement', 'Security', 'OptIn', 'DefaultChange', 'Informational') {
        $ByCategory[$Name] = @($Sorted | Where-Object { $_.Category -eq $Name }).Count
    }
    $Oldest = if ($CacheTimes.Count -gt 0) { ($CacheTimes | Sort-Object | Select-Object -First 1) } else { $null }

    [pscustomobject]@{
        Items   = $Sorted
        Summary = [pscustomobject]@{
            Total          = $Sorted.Count
            Actionable     = @($Sorted | Where-Object { $_.Notify }).Count
            DueSoon        = @($Sorted | Where-Object { $_.DueSoon }).Count
            Overdue        = @($Sorted | Where-Object { $_.DeadlineStatus -eq 'Overdue' }).Count
            ByCategory     = [pscustomobject]$ByCategory
            PostsRead      = $ById.Count
            TenantsCovered = $MessagesByTenant.Count
            NotCached      = [string[]]$NotCached
            Source         = $Source
            OldestCache    = if ($Oldest) { Format-CIPPCentralTime -Value $Oldest } else { '' }
            Days           = $Days
            DeadlineDays   = $DeadlineDays
            TenantFilter   = $TenantFilter
        }
        Errors  = [string[]]$Errors.ToArray()
    }
}
