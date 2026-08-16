function Get-CIPPStorageArchivalCandidate {
    <#
    .SYNOPSIS
        Identify SharePoint sites that are genuinely worth archiving.
    .DESCRIPTION
        "Inactive for more than 90 days" on its own is close to useless as an archival
        signal. Checked against a real tenant, 13 of Trinity Bay's sites are dormant and
        none of them are archivable: Tenant Admin Site, Compliance Policy Center, Video
        Portal, My Site Host, Enterprise Search Center and the Content Type Hub are
        infrastructure that Microsoft provisions and never touches again. A report whose
        first recommendation is "delete these six things you must not delete" does not get
        read twice.

        So a candidate has to clear three bars:
          - not a system site (by root web template, and by URL for the ones whose template
            is indistinguishable from a real team site)
          - not a personal OneDrive - a dormant OneDrive is a leavers/offboarding question,
            handled elsewhere, not a SharePoint archival one
          - big enough and idle long enough to be worth anyone's time

        A site with no recorded activity date at all is treated as UNKNOWN, not as inactive.
        Never-used and never-reported look identical in the data, and recommending deletion
        of something we simply have no telemetry for is the same mistake in a different
        costume. Those are returned separately so the report can say so.

    .PARAMETER Sites
        Site records, as stored by Push-CIPPStorageSnapshot from the SiteActivity cache.
    .PARAMETER InactiveDays
        How long a site must have been idle to qualify.
    .PARAMETER MinBytes
        Size floor. Reclaiming 2 MB is not worth a conversation.
    .PARAMETER AsOf
        Date to measure inactivity against. Defaults to today; supplied by tests.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$Sites,
        [int]$InactiveDays = 90,
        [long]$MinBytes = 1GB,
        [datetime]$AsOf = (Get-Date)
    )

    # Root web templates Microsoft provisions for its own use. Dormancy is their normal
    # state, so inactivity carries no information about them.
    $SystemTemplates = @(
        'Tenant Admin Site'
        'My Site Host'
        'Compliance Policy Center'
        'Enterprise Search Center'
        'Video Portal'
        'Video Channel / Knowledge Magazine'
        'Redirect Site'
        'App Catalog Site'
        'Point Publishing Hub'
        'Team Channel'
    )
    # Sites whose template is indistinguishable from a genuine one - the Content Type Hub
    # reports as 'Team Site'. Matched on URL instead.
    $SystemUrlPatterns = @('/sites/contentTypeHub', '/search$', '/portals/hub')

    $Candidates = [System.Collections.Generic.List[object]]::new()
    $UnknownActivity = [System.Collections.Generic.List[object]]::new()
    $Cutoff = $AsOf.AddDays(-$InactiveDays)

    foreach ($Site in @($Sites)) {
        if (-not $Site) { continue }
        if ($Site.isPersonalSite -eq $true) { continue }
        if ($Site.isDeleted -eq $true) { continue }

        $Template = [string]$Site.rootWebTemplate
        if ($SystemTemplates -contains $Template) { continue }

        $Url = [string]$Site.webUrl
        $IsSystemUrl = $false
        foreach ($Pattern in $SystemUrlPatterns) {
            if ($Url -match $Pattern) { $IsSystemUrl = $true; break }
        }
        if ($IsSystemUrl) { continue }

        $Bytes = 0L
        if ($null -ne $Site.sharePointStorageUsedInBytes) {
            try { $Bytes = [long]$Site.sharePointStorageUsedInBytes } catch { $Bytes = 0L }
        }
        if ($Bytes -lt $MinBytes) { continue }

        $Raw = $Site.effectiveLastActivityDate
        if (-not $Raw) { $Raw = $Site.sharePointLastActivityDate }
        if (-not $Raw) {
            $UnknownActivity.Add([pscustomobject]@{
                    Name         = [string]$Site.displayName
                    Url          = $Url
                    Template     = $Template
                    StorageBytes = $Bytes
                    FileCount    = [long]($Site.sharePointFileCount ?? 0)
                })
            continue
        }

        $LastActivity = $null
        try { $LastActivity = [datetime]::Parse([string]$Raw, [cultureinfo]::InvariantCulture) } catch {}
        if (-not $LastActivity) {
            $UnknownActivity.Add([pscustomobject]@{
                    Name         = [string]$Site.displayName
                    Url          = $Url
                    Template     = $Template
                    StorageBytes = $Bytes
                    FileCount    = [long]($Site.sharePointFileCount ?? 0)
                })
            continue
        }

        if ($LastActivity -le $Cutoff) {
            $Candidates.Add([pscustomobject]@{
                    Name         = [string]$Site.displayName
                    Url          = $Url
                    Template     = $Template
                    StorageBytes = $Bytes
                    FileCount    = [long]($Site.sharePointFileCount ?? 0)
                    LastActivity = $LastActivity.ToString('yyyy-MM-dd')
                    IdleDays     = [int]($AsOf - $LastActivity).TotalDays
                })
        }
    }

    return [pscustomobject]@{
        Candidates      = @($Candidates | Sort-Object -Property StorageBytes -Descending)
        UnknownActivity = @($UnknownActivity | Sort-Object -Property StorageBytes -Descending)
        ReclaimableBytes = [long](@($Candidates | Measure-Object -Property StorageBytes -Sum).Sum)
    }
}
