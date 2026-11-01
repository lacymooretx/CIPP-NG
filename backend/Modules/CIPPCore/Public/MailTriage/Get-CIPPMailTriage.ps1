function Get-CIPPMailTriage {
    <#
    .SYNOPSIS
        Guided "mail not received / delayed" triage for one recipient: runs nine read-only checks and returns an evidence bundle.
    .DESCRIPTION
        Order: Service Health (open Exchange Online incidents/advisories), message trace (Get-MessageTraceV2 for the
        window), quarantine (admin view for the recipient), mail flow rules that name the sender/recipient/domain,
        the recipient's inbox rules including hidden ones, sender/delivery restrictions and forwarding, mailbox quota
        and archive, Tenant Allow/Block List and the user's Blocked Senders, and the account's sign-in state.
        Each step is graded by Resolve-CIPPMailTriageStep (OK / Problem / Unknown); a step that cannot be read is
        Unknown with the error, and never stops the others. All times are US Central with UTC alongside.
        Every call is a Get-*; nothing is changed. Aspendora fork addition (Vikunja CIPP-38).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [Parameter(Mandatory)][string]$Recipient,
        [string]$Sender,
        [ValidateRange(1, 240)][int]$Hours = 48
    )

    $Recipient = $Recipient.Trim()
    $Sender = ([string]$Sender).Trim()
    $EndUtc = [DateTime]::UtcNow
    $StartUtc = $EndUtc.AddHours(-$Hours)
    $IsoFormat = 'yyyy-MM-ddTHH:mm:ssZ'

    $Accepted = @(try { New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-AcceptedDomain' | ForEach-Object { [string]$_.DomainName } } catch { @() })
    $Mailbox = $null
    $MailboxError = $null
    try {
        $Mailbox = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-Mailbox' -cmdParams @{ Identity = $Recipient } -Anchor $Recipient
    } catch {
        $MailboxError = (Get-CippException -Exception $_).NormalizedError
    }
    $RecipientObject = $Mailbox
    if (-not $RecipientObject) {
        # Groups, mail users and contacts carry the same restriction properties.
        try { $RecipientObject = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-Recipient' -cmdParams @{ Identity = $Recipient } } catch { $RecipientObject = $null }
    }
    # Trace under the primary address; aliases are not matched by Get-MessageTraceV2.
    $Primary = if ($RecipientObject.PrimarySmtpAddress) { [string]$RecipientObject.PrimarySmtpAddress } else { $Recipient }
    $Context = @{ Recipient = $Primary; Sender = $Sender; AcceptedDomains = $Accepted }

    $Steps = [System.Collections.Generic.List[object]]::new()
    $Run = {
        param([string]$Key, [string]$Title, [scriptblock]$Collect)
        $Started = [DateTime]::UtcNow
        try {
            $Data = & $Collect
            $Result = Resolve-CIPPMailTriageStep -Key $Key -Data $Data -Context $Context
        } catch {
            $Result = [pscustomobject]@{ Status = 'Unknown'; Summary = "Could not check: $((Get-CippException -Exception $_).NormalizedError)"; Findings = @(); Evidence = $null }
        }
        $Steps.Add([pscustomobject]@{
                Order     = $Steps.Count + 1
                Key       = $Key
                Title     = $Title
                Status    = $Result.Status
                Summary   = $Result.Summary
                Findings  = @($Result.Findings)
                Evidence  = $Result.Evidence
                DurationS = [math]::Round(([DateTime]::UtcNow - $Started).TotalSeconds, 1)
            })
    }

    & $Run 'ServiceHealth' 'Service health (Exchange Online)' {
        @{ Issues = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/issues?`$filter=endDateTime eq null and service eq 'Exchange Online'" -tenantid $TenantFilter) }
    }
    & $Run 'MessageTrace' "Message trace (last $Hours h)" {
        $Params = @{ TenantFilter = $TenantFilter; StartUtc = $StartUtc; EndUtc = $EndUtc; RecipientAddress = @($Primary); MaxPages = 2; PageSize = 1000 }
        if ($Sender) { $Params.SenderAddress = @($Sender) }
        $Trace = Get-CIPPMessageTraceRange @Params
        @{ Rows = @($Trace.Rows); Truncated = $Trace.Truncated }
    }
    & $Run 'Quarantine' 'Quarantine (admin view)' {
        $Params = @{ RecipientAddress = @($Primary); StartReceivedDate = $StartUtc.ToString($IsoFormat); EndReceivedDate = $EndUtc.ToString($IsoFormat); PageSize = 100 }
        if ($Sender) { $Params.SenderAddress = @($Sender) }
        @{ Messages = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-QuarantineMessage' -cmdParams $Params) }
    }
    & $Run 'TransportRules' 'Mail flow (transport) rules' {
        @{ Rules = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-TransportRule') }
    }
    & $Run 'InboxRules' 'Inbox rules (including hidden)' {
        if (-not $Mailbox) { throw "Not a mailbox: $MailboxError" }
        @{ Rules = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-InboxRule' -cmdParams @{ Mailbox = $Primary; IncludeHidden = $true } -Anchor $Primary); HiddenIncluded = $true }
    }
    & $Run 'Restrictions' 'Sender and delivery restrictions' {
        @{ Recipient = $RecipientObject }
    }
    & $Run 'Quota' 'Mailbox quota and archive' {
        if (-not $Mailbox) { throw "Not a mailbox: $MailboxError" }
        $Stats = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-MailboxStatistics' -cmdParams @{ Identity = $Primary } -Anchor $Primary
        $ArchiveStats = $null
        if ($Mailbox.ArchiveStatus -eq 'Active') {
            try { $ArchiveStats = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-MailboxStatistics' -cmdParams @{ Identity = $Primary; Archive = $true } -Anchor $Primary } catch { $ArchiveStats = $null }
        }
        @{ Mailbox = $Mailbox; Stats = $Stats; ArchiveStats = $ArchiveStats }
    }
    & $Run 'SenderBlocks' 'Tenant Allow/Block List and user Blocked Senders' {
        $Tabl = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-TenantAllowBlockListItems' -cmdParams @{ ListType = 'Sender' })
        $Junk = $null
        if ($Mailbox) { try { $Junk = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-MailboxJunkEmailConfiguration' -cmdParams @{ Identity = $Primary } -Anchor $Primary } catch { $Junk = $null } }
        @{ TablSender = $Tabl; Junk = $Junk }
    }
    & $Run 'SignIn' 'Account and recent sign-ins' {
        $User = $null
        try {
            $User = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($Primary))?`$select=id,userPrincipalName,accountEnabled,signInActivity" -tenantid $TenantFilter -noPagination $true
        } catch {
            # signInActivity needs Entra ID P1 + AuditLog.Read.All; fall back to the account state alone.
            $User = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($Primary))?`$select=id,userPrincipalName,accountEnabled" -tenantid $TenantFilter -noPagination $true
        }
        $SignIns = @()
        $SignInError = $null
        if ($User.id) {
            try {
                $SignIns = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=userId eq '$($User.id)'&`$top=10&`$orderby=createdDateTime desc" -tenantid $TenantFilter -noPagination $true)
            } catch {
                $SignInError = (Get-CippException -Exception $_).NormalizedError
            }
        }
        @{ User = $User; SignIns = $SignIns; SignInError = $SignInError }
    }

    $Problems = @($Steps | Where-Object Status -EQ 'Problem')
    $Unknown = @($Steps | Where-Object Status -EQ 'Unknown')
    $Overall = if ($Problems.Count) { 'Problem' } elseif ($Unknown.Count -eq $Steps.Count) { 'Unknown' } else { 'OK' }
    $Who = if ($Sender) { "from $Sender to $Primary" } else { "to $Primary" }
    $Summary = if ($Problems.Count) {
        "$($Problems.Count) of $($Steps.Count) checks found a problem for mail $Who in the last $Hours hours. " + (($Problems | ForEach-Object { "$($_.Title): $($_.Summary)" }) -join ' ')
    } else {
        "No problem found for mail $Who in the last $Hours hours across $($Steps.Count - $Unknown.Count) checks." + ' If the user still cannot find it, get the sender''s bounce (NDR) or exact send time, check the Junk Email and Other (Focused) folders, and search the mailbox.'
    }
    if ($Unknown.Count) { $Summary += " Could not check: $(($Unknown | ForEach-Object Title) -join ', ')." }

    [pscustomobject]@{
        Tenant      = $TenantFilter
        Recipient   = $Primary
        Sender      = $Sender
        Hours       = $Hours
        WindowStart = ConvertTo-CIPPCentralTime -Value $StartUtc
        WindowEnd   = ConvertTo-CIPPCentralTime -Value $EndUtc
        GeneratedAt = ConvertTo-CIPPCentralTime -Value ([DateTime]::UtcNow)
        TimeZone    = 'Times are US Central (America/Chicago) with UTC alongside.'
        Overall     = $Overall
        Summary     = $Summary
        Steps       = @($Steps)
    }
}
