function Get-CIPPMessageCenterClassification {
    <#
    .SYNOPSIS
        Classify one Microsoft 365 Message Center post and work out its deadline.
    .DESCRIPTION
        Pure function: no Graph, no tables. Used by Get-CIPPMessageCenterDigest (the ListMessageCenterDigest page) and
        the MessageCenterDigest alert, so both always agree.

        The rules live in $Rules below, one row per category, in priority order. Every rule is checked so Flags lists
        all that matched; Category is the first match. Notify = the category is worth an alert (action required,
        retirement, security). Informational is the fallback and never notifies.

        Tuning notes, from the live tenants on 2026-11-01:
          - Almost every post carries the "Admin impact" tag, so that tag alone is never a signal.
          - Microsoft sets actionRequiredByDateTime on about 1 post in 20. It is midnight Pacific as UTC
            (e.g. 2026-11-06T07:00:00Z), so the deadline is shown as a US Central date.
          - Graph categories seen: stayInformed, planForChange, preventOrFixIssue. Severities: normal, high (critical
            exists in the schema). Tags seen: Updated message, New feature, Feature update, User impact, Admin impact,
            Retirement. "Breaking change" and "Data privacy" are documented tags and handled too.
          - Keyword rules read the title and the details "Summary" only. The HTML body mentions "security" in a
            large share of ordinary feature posts.
        Aspendora fork addition (Vikunja CIPP-37).
    .PARAMETER Message
        One serviceUpdateMessage (Graph admin/serviceAnnouncement/messages), as returned by Graph or the CIPP cache.
    .PARAMETER DeadlineDays
        A deadline this many days away or fewer (and not yet past) is DeadlineStatus 'Due soon'. Default 30.
    .PARAMETER Now
        The current time (UTC). Tests pass a fixed value.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Message,
        [int]$DeadlineDays = 30,
        [datetime]$Now = [datetime]::UtcNow
    )

    # Rule table. Each Match block gets the normalised post ($P) and returns a reason string, or nothing.
    # Order matters: the first rule that matches sets Category.
    $Rules = @(
        @{
            Category = 'ActionRequired'
            Label    = 'Action required / deadline'
            Notify   = $true
            Match    = {
                param($P)
                if ($P.Deadline) { return "Microsoft set an act-by date of $($P.DeadlineText)" }
                if ($P.Severity -in @('high', 'critical')) { return "Severity $($P.Severity)" }
                if ($P.Tags -contains 'Breaking change') { return 'Tagged Breaking change' }
                if ($P.Title -match '^\s*(\(Updated\)\s*)?Action required') { return 'Title says action required' }
            }
        }
        @{
            Category = 'Retirement'
            Label    = 'Retirement'
            Notify   = $true
            Match    = {
                param($P)
                if ($P.Tags -contains 'Retirement') { return 'Tagged Retirement' }
                if ($P.Title -match '\bretir(e|es|ed|ing|ement)\b|\bdeprecat|end of (support|life|availability)|support (ends|will end)|no longer (be )?supported|\bsunset') { return 'Title announces a retirement' }
            }
        }
        @{
            Category = 'Security'
            Label    = 'Security / compliance'
            Notify   = $true
            Match    = {
                param($P)
                if ($P.Tags -contains 'Data privacy') { return 'Tagged Data privacy' }
                if ($P.Title -match '\bsecurity\b|phish|malicious|malware|\bMFA\b|multi-?factor|authenticat|conditional access|passkey|FIDO|impersonat|compromis|vulnerab|CVE-|certificate authorit|encrypt|anti-?bot|CAPTCHA|threat|spoof|DMARC|DKIM|\bTLS\b|legacy auth|basic auth|SMTP AUTH|safe links|quarantine') {
                    return 'Security keyword in title'
                }
                # A security product's own planned changes. stayInformed feature posts from these services are left out.
                $SecurityService = @($P.Services | Where-Object { $_ -match '^Microsoft (Defender|Entra|Purview)|Identity Service|Information Protection' })
                if ($SecurityService.Count -gt 0 -and ($P.MsCategory -in @('planForChange', 'preventOrFixIssue') -or $P.IsMajorChange)) {
                    return "Planned change to $($SecurityService[0])"
                }
            }
        }
        @{
            Category = 'OptIn'
            Label    = 'New feature off by default / opt-in'
            Notify   = $false
            Match    = {
                param($P)
                if ($P.Text -match "off by default|disabled by default|(not|n't)( be)? (enabled|on|turned on) by default|\bopt[- ]in\b|admins? (can|must|need to|will need to) (enable|turn on|opt)|requires? admin (enablement|opt)") {
                    return 'Admins must turn it on'
                }
            }
        }
        @{
            Category = 'DefaultChange'
            Label    = 'On by default (admin opt-out)'
            Notify   = $false
            Match    = {
                param($P)
                # "not (be) enabled by default" is the opt-in wording above, so strip it before looking for "on by default".
                $Text = $P.Text -replace "(not|n't)( be)? (enabled|on|turned on) by default", ''
                if ($Text -match "\b(on|enabled) by default|default enablement|\bopt[- ]out\b|will become the default|new default") {
                    return 'Turns on or changes a default unless an admin opts out'
                }
            }
        }
    )
    $Fallback = @{ Category = 'Informational'; Label = 'Informational'; Notify = $false }

    # Dates arrive as [datetime] (CIPP cache / ConvertFrom-Json, Kind Utc or Local), [datetimeoffset] or ISO strings.
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
    $Central = try { [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { $null }
    $ToCentralDate = {
        param([datetime]$Utc)
        if ($Central) { return [System.TimeZoneInfo]::ConvertTimeFromUtc($Utc, $Central).Date }
        return $Utc.Date
    }

    $Summary = ''
    foreach ($Detail in @($Message.details)) {
        if ($Detail -and [string]$Detail.name -eq 'Summary') { $Summary = [string]$Detail.value }
    }
    $Deadline = & $ToUtc $Message.actionRequiredByDateTime
    $NowUtc = & $ToUtc $Now
    $P = [pscustomobject]@{
        Title         = [string]$Message.title
        Text          = "$([string]$Message.title) $Summary"
        Tags          = @($Message.tags | ForEach-Object { [string]$_ })
        Services      = @($Message.services | ForEach-Object { [string]$_ })
        Severity      = ([string]$Message.severity).ToLowerInvariant()
        MsCategory    = [string]$Message.category
        IsMajorChange = [bool]$Message.isMajorChange
        Deadline      = $Deadline
        DeadlineText  = if ($Deadline) { (& $ToCentralDate $Deadline).ToString('yyyy-MM-dd') } else { '' }
    }

    $Matched = $null
    $Flags = [System.Collections.Generic.List[string]]::new()
    $Reasons = [System.Collections.Generic.List[string]]::new()
    foreach ($Rule in $Rules) {
        $Reason = & $Rule.Match $P
        if ([string]::IsNullOrWhiteSpace([string]$Reason)) { continue }
        $Flags.Add($Rule.Category)
        $Reasons.Add([string]$Reason)
        if (-not $Matched) { $Matched = $Rule }
    }
    if (-not $Matched) { $Matched = $Fallback }

    # Days left counts calendar days in US Central, so a deadline of "tomorrow" is 1 whatever the hour.
    $DaysLeft = $null
    $Status = ''
    if ($Deadline) {
        $DaysLeft = [int]((& $ToCentralDate $Deadline) - (& $ToCentralDate $NowUtc)).TotalDays
        $Status = if ($DaysLeft -lt 0) { 'Overdue' } elseif ($DaysLeft -le $DeadlineDays) { 'Due soon' } else { 'Upcoming' }
    }

    [pscustomobject]@{
        Category       = $Matched.Category
        CategoryLabel  = $Matched.Label
        Notify         = [bool]$Matched.Notify
        Flags          = [string[]]$Flags.ToArray()
        Reasons        = [string[]]$Reasons.ToArray()
        Summary        = $Summary
        DeadlineUtc    = $Deadline
        Deadline       = $P.DeadlineText
        DaysLeft       = $DaysLeft
        DeadlineStatus = $Status
        DueSoon        = $Status -eq 'Due soon'
    }
}
