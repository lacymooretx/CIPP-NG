function Get-CIPPOooExposure {
    <#
    .SYNOPSIS
        Lists mailboxes whose automatic reply is live for external senders and flags what the message gives away.
    .DESCRIPTION
        Read only. Shared by ListOooExposure (the Out-of-office Exposure page) and the OooExposure scripted alert.

        Why: an external out-of-office reply tells anyone who emails the mailbox that the person is away, until when,
        and often who to contact instead. That is the timing and the impersonation target for BEC payment fraud.

        Calls, all through Exchange Online (no per-mailbox round trips):
          1. Get-Mailbox (user + shared mailboxes, paged) and Get-AcceptedDomain.
          2. Get-MailboxAutoReplyConfiguration for every mailbox in one New-ExoBulkRequest (10 per $batch, up to 16
             batches in flight), projected to state, audience and schedule only. The cmdlet has no tenant-wide form:
             without -Identity it fails "Mandatory parameter not satisfied" (verified 2026-11-01), and its Identity
             comes back as the display name, so each sub-request is keyed by UPN through OperationGuid.
          3. A second bulk request reads ExternalMessage only for the mailboxes that are live externally, so message
             bodies of everyone else are never fetched.

        A mailbox is reported when AutoReplyState is Enabled, or Scheduled and now inside StartTime..EndTime
        (-IncludeUpcoming also returns schedules starting within -UpcomingDays), and ExternalAudience is All or Known.
        Flags come from Get-CIPPOooMessageFlags; severity from Get-CIPPOooExposureSeverity (High / Medium / Low).
        Times are returned as UTC ISO strings, Unix seconds (for the existing ExecSetOoO endpoint) and US Central text.

        A tenant with no Exchange Online licence returns Status 'NoExchange' (Info), not an error.
        Aspendora fork addition (Vikunja CIPP-40).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [switch]$IncludeUpcoming,
        [int]$UpcomingDays = 14,
        # Injected by tests; the real caller always uses the current time.
        [datetime]$Now = [datetime]::UtcNow
    )

    $Now = $Now.ToUniversalTime()
    $Errors = [System.Collections.Generic.List[string]]::new()
    $Result = [ordered]@{
        Tenant           = $TenantFilter
        GeneratedAt      = $Now.ToString('yyyy-MM-ddTHH:mm:ssZ')
        GeneratedCentral = Format-CIPPCentralTime $Now
        Status           = 'OK'
        Message          = ''
        MailboxesChecked = 0
        # Mailboxes whose auto-reply settings came back. 0 with MailboxesChecked > 0 means the read failed outright.
        SettingsRead     = 0
        Summary          = [ordered]@{ High = 0; Medium = 0; Low = 0; Total = 0 }
        Rows             = @()
        Errors           = @()
    }

    # EXO returns StartTime/EndTime as ISO strings or, after JSON parsing, as DateTime; normalise to UTC either way.
    $ToUtc = {
        param($Value)
        if ($null -eq $Value -or [string]$Value -eq '') { return $null }
        try {
            $When = if ($Value -is [datetime]) { ([datetime]$Value).ToUniversalTime() } else { ([datetimeoffset][string]$Value).UtcDateTime }
            if ($When.Year -le 1) { return $null }
            return $When
        } catch { return $null }
    }

    if (-not (Test-CIPPStandardLicense -StandardName 'OooExposure' -TenantFilter $TenantFilter -Preset Exchange -SkipLog)) {
        $Result.Status = 'NoExchange'
        $Result.Message = 'This tenant has no Exchange Online licence, so there are no auto-replies to check.'
        return [pscustomobject]$Result
    }

    try {
        $Mailboxes = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-Mailbox' -cmdParams @{
                Filter = "RecipientTypeDetails -eq 'UserMailbox' -or RecipientTypeDetails -eq 'SharedMailbox'"
            } -Select 'UserPrincipalName,PrimarySmtpAddress,DisplayName,RecipientTypeDetails,EmailAddresses' -ErrorAction Stop |
                Where-Object { $_.UserPrincipalName })
    } catch {
        $Message = (Get-CippException -Exception $_).NormalizedError
        # Licensing / not-provisioned answers are a property of the tenant, not a failure (see Get-CIPPAlertFailureSeverity).
        if ((Get-CIPPAlertFailureSeverity -ErrorText $Message) -eq 'Info' -or $Message -match 'Exchange Online.*(not|isn''t)|no Exchange|not.*Exchange Online|ExchangeOnline.*not') {
            $Result.Status = 'NoExchange'
            $Result.Message = "Exchange Online is not available for this tenant: $Message"
            return [pscustomobject]$Result
        }
        throw "Could not list mailboxes: $Message"
    }
    $Result.MailboxesChecked = $Mailboxes.Count
    if ($Mailboxes.Count -eq 0) { return [pscustomobject]$Result }

    $AcceptedDomains = @()
    try {
        $AcceptedDomains = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-AcceptedDomain' -Select 'DomainName' -ErrorAction Stop | ForEach-Object { [string]$_.DomainName } | Where-Object { $_ })
    } catch {
        $Errors.Add("Accepted domains could not be read, so internal and external addresses are not told apart: $((Get-CippException -Exception $_).NormalizedError)")
    }

    $ByUpn = @{}
    foreach ($Mailbox in $Mailboxes) { $ByUpn[([string]$Mailbox.UserPrincipalName).ToLowerInvariant()] = $Mailbox }

    # Pass 1: state, audience and schedule for every mailbox. No message bodies.
    $StateRequests = foreach ($Mailbox in $Mailboxes) {
        @{
            CmdletInput   = @{ CmdletName = 'Get-MailboxAutoReplyConfiguration'; Parameters = @{ Identity = [string]$Mailbox.UserPrincipalName } }
            OperationGuid = ([string]$Mailbox.UserPrincipalName).ToLowerInvariant()
        }
    }
    $States = @{}
    $StateErrors = 0
    foreach ($Item in @(New-ExoBulkRequest -tenantid $TenantFilter -cmdletArray @($StateRequests) -Select 'AutoReplyState,ExternalAudience,StartTime,EndTime' -MaxConcurrency 16)) {
        if (-not $Item.OperationGuid) { continue }
        if ($Item.PSObject.Properties['error'] -and $Item.error) { $StateErrors++; continue }
        $States[[string]$Item.OperationGuid] = $Item
    }
    $Result.SettingsRead = $States.Count
    $Missing = $Mailboxes.Count - $States.Count - $StateErrors
    if ($StateErrors -gt 0 -or $Missing -gt 0) {
        $Errors.Add("Auto-reply settings could not be read for $($StateErrors + [math]::Max(0, $Missing)) of $($Mailboxes.Count) mailboxes.")
    }

    # Which mailboxes are live for external senders right now (or soon, with -IncludeUpcoming).
    $Live = [System.Collections.Generic.List[object]]::new()
    foreach ($Key in $States.Keys) {
        $State = $States[$Key]
        $Audience = [string]$State.ExternalAudience
        if ($Audience -notin @('All', 'Known')) { continue }
        $Start = & $ToUtc $State.StartTime
        $End = & $ToUtc $State.EndTime
        $Window = switch ([string]$State.AutoReplyState) {
            'Enabled' { 'Active' }
            'Scheduled' {
                if ($Start -and $End -and $Start -le $Now -and $Now -lt $End) { 'Active' }
                elseif ($IncludeUpcoming -and $Start -and $Start -gt $Now -and $Start -le $Now.AddDays($UpcomingDays)) { 'Upcoming' }
                else { $null }
            }
            default { $null }
        }
        if (-not $Window) { continue }
        $Live.Add([pscustomobject]@{ Key = $Key; State = $State; Audience = $Audience; Window = $Window; Start = $Start; End = $End })
    }

    # Pass 2: the external message, for the live mailboxes only.
    $Messages = @{}
    $MessageErrors = @{}
    if ($Live.Count -gt 0) {
        $MessageRequests = foreach ($Entry in $Live) {
            @{
                CmdletInput   = @{ CmdletName = 'Get-MailboxAutoReplyConfiguration'; Parameters = @{ Identity = [string]$ByUpn[$Entry.Key].UserPrincipalName } }
                OperationGuid = $Entry.Key
            }
        }
        foreach ($Item in @(New-ExoBulkRequest -tenantid $TenantFilter -cmdletArray @($MessageRequests) -Select 'ExternalMessage' -MaxConcurrency 16)) {
            if (-not $Item.OperationGuid) { continue }
            if ($Item.PSObject.Properties['error'] -and $Item.error) { $MessageErrors[[string]$Item.OperationGuid] = [string]$Item.error; continue }
            $Messages[[string]$Item.OperationGuid] = [string]$Item.ExternalMessage
        }
    }

    $Rank = @{ High = 0; Medium = 1; Low = 2 }
    $Rows = foreach ($Entry in $Live) {
        $Mailbox = $ByUpn[$Entry.Key]
        $Own = @([string]$Mailbox.UserPrincipalName, [string]$Mailbox.PrimarySmtpAddress) + @($Mailbox.EmailAddresses | ForEach-Object { [string]$_ } | Where-Object { $_ -like 'smtp:*' } | ForEach-Object { $_.Substring(5) })
        $MessageRead = $Messages.ContainsKey($Entry.Key)
        $Scan = Get-CIPPOooMessageFlags -Message ($MessageRead ? $Messages[$Entry.Key] : '') -AcceptedDomains $AcceptedDomains -OwnAddresses $Own
        $Severity = Get-CIPPOooExposureSeverity -ExternalAudience $Entry.Audience -Flags $Scan.Flags
        $Reasons = [System.Collections.Generic.List[string]]::new()
        if ($Scan.InternalEmails.Count -gt 0) { $Reasons.Add("names colleague address(es) $($Scan.InternalEmails -join ', ')") }
        if ($Scan.ExternalEmails.Count -gt 0) { $Reasons.Add("names external address(es) $($Scan.ExternalEmails -join ', ')") }
        if ($Scan.PhoneCount -gt 0) { $Reasons.Add("contains $($Scan.PhoneCount) phone number(s)") }
        if ($Scan.FinanceTerms.Count -gt 0) { $Reasons.Add("mentions finance: $($Scan.FinanceTerms -join ', ')") }
        if ($Scan.Titles.Count -gt 0) { $Reasons.Add("gives job titles: $($Scan.Titles -join ', ')") }
        if ($Scan.TravelTerms.Count -gt 0) { $Reasons.Add("mentions travel: $($Scan.TravelTerms -join ', ')") }
        if ($Scan.Dates.Count -gt 0) { $Reasons.Add("gives a return date: $($Scan.Dates -join ', ')") }
        if (-not $MessageRead) { $Reasons.Add("could not be read$(if ($MessageErrors[$Entry.Key]) { ": $($MessageErrors[$Entry.Key])" })") }
        $IsScheduled = [string]$Entry.State.AutoReplyState -eq 'Scheduled'
        [pscustomobject]@{
            Mailbox             = [string]$Mailbox.UserPrincipalName
            DisplayName         = [string]$Mailbox.DisplayName
            RecipientType       = [string]$Mailbox.RecipientTypeDetails
            Severity            = $Severity
            SeverityRank        = $Rank[$Severity]
            AutoReplyState      = [string]$Entry.State.AutoReplyState
            ExternalAudience    = $Entry.Audience
            Window              = $Entry.Window
            # The schedule only means something for Scheduled; EXO keeps stale times on Enabled replies.
            StartTime           = if ($IsScheduled -and $Entry.Start) { $Entry.Start.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
            EndTime             = if ($IsScheduled -and $Entry.End) { $Entry.End.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
            StartTimeUnix       = if ($IsScheduled -and $Entry.Start) { [int64]([datetimeoffset]$Entry.Start).ToUnixTimeSeconds() } else { $null }
            EndTimeUnix         = if ($IsScheduled -and $Entry.End) { [int64]([datetimeoffset]$Entry.End).ToUnixTimeSeconds() } else { $null }
            StartCentral        = if ($IsScheduled) { Format-CIPPCentralTime $Entry.Start } else { '' }
            EndCentral          = if ($IsScheduled) { Format-CIPPCentralTime $Entry.End } else { 'No end (Enabled)' }
            Flags               = @($Scan.Flags)
            FlagsText           = (@($Scan.Flags) -join ', ')
            Reasons             = ($Reasons -join '; ')
            InternalContacts    = ($Scan.InternalEmails -join ', ')
            PhoneCount          = $Scan.PhoneCount
            Snippet             = $Scan.Snippet
            # Full plain text for the report page. Alerts drop this field (Get-CIPPAlertOooExposure).
            ExternalMessageText = $Scan.Text
            MessageRead         = $MessageRead
            Recommendation      = if ($Entry.Audience -eq 'All') { 'Limit external replies to known senders (ExternalAudience Known), and remove colleague addresses, phone numbers and payment instructions from the external message.' } else { 'External replies already go to known senders only.' }
        }
    }
    $Rows = @($Rows | Sort-Object -Property SeverityRank, Mailbox)

    $Result.Rows = $Rows
    $Result.Summary.High = @($Rows | Where-Object Severity -EQ 'High').Count
    $Result.Summary.Medium = @($Rows | Where-Object Severity -EQ 'Medium').Count
    $Result.Summary.Low = @($Rows | Where-Object Severity -EQ 'Low').Count
    $Result.Summary.Total = $Rows.Count
    $Result.Errors = @($Errors)
    return [pscustomobject]$Result
}
