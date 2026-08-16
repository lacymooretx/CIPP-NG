function Get-CIPPEmailSecurityReportData {
    <#
    .SYNOPSIS
        Gather the Email Security Configuration Document model for a single tenant.
    .DESCRIPTION
        Phase 4 of the tenant documentation set: how mail flow and mail security are
        actually configured - transport rules, connectors, the anti-spam/malware/phishing
        stack, Safe Links and Safe Attachments, quarantine and allow/block lists, and
        whether the tenant's domains are actually authenticated.

        Sourced from the Exo* DB caches, which are populated for every tenant by the
        CIPPDBCache tasks, with a defensive live fallback only where no cache exists.
        Same contract as the Intune and Identity builders: stable section Keys for the IT
        Glue trait mapping, defensive per-section collection, and a section that could not
        be read is recorded as a note rather than rendered as an empty tenant.
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

    # Read a DB cache type and rehydrate each row's payload. Count rows are metadata, not
    # data. A cache that is empty returns nothing rather than throwing, so callers can tell
    # "nothing configured" from "collection failed" themselves.
    function Get-CachedItems([string]$Type) {
        $Out = [System.Collections.Generic.List[object]]::new()
        $Rows = @(Get-CIPPDbItem -TenantFilter $TenantFilter -Type $Type | Where-Object { $_.RowKey -notlike '*-Count' })
        foreach ($Row in $Rows) {
            if (-not $Row.Data) { continue }
            try {
                $Parsed = $Row.Data | ConvertFrom-Json -Depth 20 -ErrorAction Stop
                foreach ($Item in @($Parsed)) { if ($null -ne $Item) { $Out.Add($Item) } }
            } catch {
                $Notes.Add(@{ Section = $Type; Detail = "Could not parse a cached $Type row: $($_.Exception.Message)" })
            }
        }
        return $Out
    }

    # ---- tenant identity -----------------------------------------------------------
    $Org = $null
    try { $Org = New-GraphGetRequest -uri "$GraphBeta/organization" -tenantid $TenantFilter | Select-Object -First 1 } catch {}
    $TenantName = if ($Org.displayName) { $Org.displayName } else { $TenantFilter }
    $DefaultDomain = ($Org.verifiedDomains | Where-Object { $_.isDefault }).name
    if (-not $DefaultDomain) { $DefaultDomain = $TenantFilter }

    # Section closures run in a child scope; anything the findings need back lives here.
    $State = @{ Count = 0; EnabledRules = 0; DmarcEnforced = 0; DomainCount = 0; SafeLinks = 0 }

    # ---- Transport Rules -----------------------------------------------------------
    # The highest-risk thing in a tenant's mail configuration, and the least documented:
    # a forgotten bypass rule is how phishing keeps reaching a mailbox nobody can explain.
    Invoke-Section 'TransportRules' 'Transport Rules' {
        $Rules = Get-CachedItems 'ExoTransportRules'
        $r = New-RowList
        foreach ($Rule in ($Rules | Sort-Object { [int]($_.Priority ?? 999) })) {
            $Desc = ([string]$Rule.Description) -replace '\s+', ' '
            $r.Add(@(
                    [string]$Rule.Name,
                    [string]$Rule.State,
                    [string]$Rule.Priority,
                    [string]$Rule.Mode,
                    $Desc.Trim(),
                    (([string]$Rule.Comments) -replace '\s+', ' ').Trim()
                ))
        }
        $State.EnabledRules = @($Rules | Where-Object { $_.State -eq 'Enabled' }).Count
        $State.Count += $Rules.Count
        Add-Section 'TransportRules' 'Transport Rules' 'info' `
            "$($Rules.Count) mail flow rules, $($State.EnabledRules) enabled. Listed in priority order - the order they are evaluated." `
            @('Rule', 'State', 'Priority', 'Mode', 'What it does', 'Comments') $r `
            'No transport rules are configured. Mail flow follows Exchange Online defaults.'
    }

    # ---- Mail Flow Connectors ------------------------------------------------------
    Invoke-Section 'Connectors' 'Mail Flow Connectors' {
        $r = New-RowList
        $Inbound = Get-CachedItems 'ExoInboundConnector'
        foreach ($c in $Inbound) {
            $Detail = @(
                if ($c.SenderDomains) { "Sender domains: $((@($c.SenderDomains) -join ', '))" }
                if ($c.SenderIPAddresses) { "Sender IPs: $((@($c.SenderIPAddresses) -join ', '))" }
                if ($null -ne $c.RequireTls) { "Require TLS: $($c.RequireTls)" }
            ) -join ' | '
            $r.Add(@('Inbound', [string]$c.Name, "$($c.Enabled)", [string]$c.ConnectorType, $Detail))
        }
        # No outbound connector cache exists, so this one is read live.
        $Outbound = @()
        try {
            $Outbound = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-OutboundConnector')
        } catch {
            $Notes.Add(@{ Section = 'Mail Flow Connectors'; Detail = "Outbound connectors unavailable: $($_.Exception.Message)" })
        }
        foreach ($c in $Outbound) {
            $Detail = @(
                if ($c.SmartHosts) { "Smart hosts: $((@($c.SmartHosts) -join ', '))" }
                if ($c.RecipientDomains) { "Recipient domains: $((@($c.RecipientDomains) -join ', '))" }
                if ($null -ne $c.TlsSettings) { "TLS: $($c.TlsSettings)" }
            ) -join ' | '
            $r.Add(@('Outbound', [string]$c.Name, "$($c.Enabled)", [string]$c.ConnectorType, $Detail))
        }
        $State.Count += ($Inbound.Count + @($Outbound).Count)
        Add-Section 'Connectors' 'Mail Flow Connectors' 'info' `
            "$($Inbound.Count) inbound, $(@($Outbound).Count) outbound connectors." `
            @('Direction', 'Connector', 'Enabled', 'Type', 'Configuration') $r `
            'No mail flow connectors. Mail routes directly through Exchange Online.'
    }

    # ---- Anti-Spam, Malware and Phishing -------------------------------------------
    Invoke-Section 'AntiSpamAndMalware' 'Anti-Spam, Malware and Phishing' {
        $r = New-RowList
        foreach ($p in (Get-CachedItems 'ExoHostedContentFilterPolicy')) {
            $Detail = @(
                if ($p.SpamAction) { "Spam: $($p.SpamAction)" }
                if ($p.HighConfidenceSpamAction) { "High confidence: $($p.HighConfidenceSpamAction)" }
                if ($p.PhishSpamAction) { "Phish: $($p.PhishSpamAction)" }
                if ($p.BulkThreshold) { "Bulk threshold: $($p.BulkThreshold)" }
            ) -join ' | '
            $r.Add(@('Anti-Spam (inbound)', [string]$p.Name, "$($p.IsDefault)", $Detail))
        }
        foreach ($p in (Get-CachedItems 'ExoHostedOutboundSpamFilterPolicy')) {
            $Detail = @(
                if ($p.RecipientLimitExternalPerHour) { "External/hr: $($p.RecipientLimitExternalPerHour)" }
                if ($p.ActionWhenThresholdReached) { "Action: $($p.ActionWhenThresholdReached)" }
                if ($null -ne $p.AutoForwardingMode) { "Auto-forwarding: $($p.AutoForwardingMode)" }
            ) -join ' | '
            $r.Add(@('Anti-Spam (outbound)', [string]$p.Name, "$($p.IsDefault)", $Detail))
        }
        foreach ($p in (Get-CachedItems 'ExoMalwareFilterPolicies')) {
            $Detail = @(
                if ($null -ne $p.EnableFileFilter) { "File filter: $($p.EnableFileFilter)" }
                if ($p.FileTypes) { "Blocked types: $((@($p.FileTypes) | Select-Object -First 12) -join ', ')" }
                if ($null -ne $p.ZapEnabled) { "ZAP: $($p.ZapEnabled)" }
            ) -join ' | '
            $r.Add(@('Anti-Malware', [string]$p.Name, "$($p.IsDefault)", $Detail))
        }
        foreach ($p in (Get-CachedItems 'ExoAntiPhishPolicies')) {
            $Detail = @(
                if ($null -ne $p.EnableSpoofIntelligence) { "Spoof intelligence: $($p.EnableSpoofIntelligence)" }
                if ($null -ne $p.EnableMailboxIntelligence) { "Mailbox intelligence: $($p.EnableMailboxIntelligence)" }
                if ($p.AuthenticationFailAction) { "Auth fail: $($p.AuthenticationFailAction)" }
                if ($null -ne $p.EnableTargetedUserProtection) { "Impersonation protection: $($p.EnableTargetedUserProtection)" }
            ) -join ' | '
            $r.Add(@('Anti-Phishing', [string]$p.Name, "$($p.IsDefault)", $Detail))
        }
        $State.Count += $r.Count
        Add-Section 'AntiSpamAndMalware' 'Anti-Spam, Malware and Phishing' 'info' `
            "$($r.Count) filter policies across inbound spam, outbound spam, malware and phishing." `
            @('Type', 'Policy', 'Default', 'Configuration') $r `
            'No filter policies could be read for this tenant.'
    }

    # ---- Safe Links and Safe Attachments -------------------------------------------
    Invoke-Section 'SafeLinksAndAttachments' 'Safe Links and Safe Attachments' {
        $r = New-RowList
        $SafeLinks = Get-CachedItems 'ExoSafeLinksPolicies'
        foreach ($p in $SafeLinks) {
            $Detail = @(
                if ($null -ne $p.EnableSafeLinksForEmail) { "Email: $($p.EnableSafeLinksForEmail)" }
                if ($null -ne $p.EnableSafeLinksForTeams) { "Teams: $($p.EnableSafeLinksForTeams)" }
                if ($null -ne $p.EnableSafeLinksForOffice) { "Office: $($p.EnableSafeLinksForOffice)" }
                if ($null -ne $p.ScanUrls) { "Scan URLs: $($p.ScanUrls)" }
                if ($null -ne $p.DeliverMessageAfterScan) { "Wait for scan: $($p.DeliverMessageAfterScan)" }
            ) -join ' | '
            $r.Add(@('Safe Links', [string]$p.Name, "$($p.IsEnabled)", $Detail))
        }
        $SafeAttach = Get-CachedItems 'ExoSafeAttachmentPolicies'
        foreach ($p in $SafeAttach) {
            $Detail = @(
                if ($p.Action) { "Action: $($p.Action)" }
                if ($null -ne $p.Enable) { "Enabled: $($p.Enable)" }
                if ($p.Redirect) { "Redirect: $($p.Redirect)" }
            ) -join ' | '
            $r.Add(@('Safe Attachments', [string]$p.Name, "$($p.IsEnabled)", $Detail))
        }
        foreach ($p in (Get-CachedItems 'ExoAtpPolicyForO365')) {
            $Detail = @(
                if ($null -ne $p.EnableSafeDocs) { "Safe Docs: $($p.EnableSafeDocs)" }
                if ($null -ne $p.EnableATPForSPOTeamsODB) { "SharePoint/Teams/OneDrive: $($p.EnableATPForSPOTeamsODB)" }
            ) -join ' | '
            $r.Add(@('Defender for Office 365', [string]$p.Name, '', $Detail))
        }
        $State.SafeLinks = $SafeLinks.Count
        $State.Count += $r.Count
        Add-Section 'SafeLinksAndAttachments' 'Safe Links and Safe Attachments' 'info' `
            "$($SafeLinks.Count) Safe Links policies, $($SafeAttach.Count) Safe Attachments policies." `
            @('Type', 'Policy', 'Enabled', 'Configuration') $r `
            'No Safe Links or Safe Attachments policies. The tenant may not be licensed for Defender for Office 365.'
    }

    # ---- Quarantine and Allow/Block Lists ------------------------------------------
    Invoke-Section 'QuarantineAndLists' 'Quarantine and Allow/Block Lists' {
        $r = New-RowList
        foreach ($p in (Get-CachedItems 'ExoQuarantinePolicy')) {
            $Detail = @(
                if ($p.EndUserQuarantinePermissionsValue) { "Permissions value: $($p.EndUserQuarantinePermissionsValue)" }
                if ($null -ne $p.ESNEnabled) { "End-user notifications: $($p.ESNEnabled)" }
            ) -join ' | '
            $r.Add(@('Quarantine Policy', [string]$p.Name, '', $Detail))
        }
        foreach ($e in (Get-CachedItems 'ExoTenantAllowBlockList')) {
            $Expiry = if ($e.ExpirationDate) {
                try { ([datetime]$e.ExpirationDate).ToString('yyyy-MM-dd') } catch { [string]$e.ExpirationDate }
            } else { '' }
            $r.Add(@("Tenant $($e.Action) List", [string]$e.Value, [string]$e.ListType, "Expires: $Expiry $(if ($e.Notes) { "| $($e.Notes)" })"))
        }
        $State.Count += $r.Count
        Add-Section 'QuarantineAndLists' 'Quarantine and Allow/Block Lists' 'info' `
            "$($r.Count) quarantine policies and tenant allow/block list entries." `
            @('Type', 'Name or Value', 'Detail', 'Configuration') $r `
            'No custom quarantine policies or tenant allow/block entries.'
    }

    # ---- Domain Authentication -----------------------------------------------------
    # SPF, DKIM and DMARC are the difference between a domain anyone can spoof and one they
    # cannot. Worth documenting per domain, not as a tenant-wide yes/no.
    Invoke-Section 'DomainAuthentication' 'Domain Authentication (SPF, DKIM, DMARC)' {
        $r = New-RowList
        $Dkim = Get-CachedItems 'ExoDkimSigningConfig'
        $Health = @()
        try { $Health = @(Get-CIPPDomainAnalyser -TenantFilter $TenantFilter) } catch {
            $Notes.Add(@{ Section = 'Domain Authentication (SPF, DKIM, DMARC)'; Detail = "Domain analyser data unavailable: $($_.Exception.Message). Run a domain analysis to populate it." })
        }
        foreach ($h in $Health) {
            $Domain = [string]$h.Domain
            $DkimEntry = $Dkim | Where-Object { $_.Domain -eq $Domain -or $_.Name -eq $Domain } | Select-Object -First 1
            $DkimState = if ($DkimEntry) { "$($DkimEntry.Enabled)" } elseif ($null -ne $h.DKIMEnabled) { "$($h.DKIMEnabled)" } else { 'Unknown' }
            $Dmarc = if ($h.DMARCPresent -eq $true) {
                $Policy = if ($h.DMARCActionPolicy) { $h.DMARCActionPolicy } else { 'none' }
                "Present (p=$Policy)"
            } else { 'Missing' }
            if ($h.DMARCActionPolicy -in @('quarantine', 'reject')) { $State.DmarcEnforced++ }
            $Spf = if ($h.SPFPassAll -eq $true) { 'Pass' } elseif ($null -eq $h.SPFPassAll) { 'Unknown' } else { 'Fail' }
            $r.Add(@($Domain, $Spf, $DkimState, $Dmarc, "$($h.Score)/$($h.MaximumScore)"))
        }
        $State.DomainCount = @($Health).Count
        $State.Count += $r.Count
        Add-Section 'DomainAuthentication' 'Domain Authentication (SPF, DKIM, DMARC)' 'info' `
            "$(@($Health).Count) domains analysed. DMARC counts as enforced only at p=quarantine or p=reject." `
            @('Domain', 'SPF', 'DKIM', 'DMARC', 'Score') $r `
            'No domain analyser results are available for this tenant yet.'
    }

    # ---- executive findings --------------------------------------------------------
    if ($State.DomainCount -gt 0) {
        if ($State.DmarcEnforced -eq 0) {
            Add-Finding 'DMARC enforcement' 'fail' "None of the $($State.DomainCount) domains publish an enforcing DMARC policy (p=quarantine or p=reject). Anyone can spoof them."
        } elseif ($State.DmarcEnforced -lt $State.DomainCount) {
            Add-Finding 'DMARC enforcement' 'warn' "$($State.DmarcEnforced) of $($State.DomainCount) domains enforce DMARC. The rest can be spoofed."
        } else {
            Add-Finding 'DMARC enforcement' 'pass' "All $($State.DomainCount) domains enforce DMARC."
        }
    }

    if ($State.SafeLinks -eq 0) {
        Add-Finding 'Safe Links' 'warn' 'No Safe Links policies. URLs in mail are not rewritten or checked at click time - confirm whether this tenant is licensed for Defender for Office 365.'
    } else {
        Add-Finding 'Safe Links' 'pass' "$($State.SafeLinks) Safe Links policies configured."
    }

    Add-Finding 'Objects documented' 'info' "$($State.Count) mail flow and mail security objects captured for $TenantName."

    if ($Notes.Count -gt 0) {
        Add-Finding 'Collection warnings' 'warn' "$($Notes.Count) section(s) could not be read in full. See collection notes."
    }

    return @{
        Title           = 'Email Security Configuration Document'
        TenantName      = $TenantName
        TenantDomain    = $DefaultDomain
        GeneratedDate   = (Get-Date).ToString('dd MMMM yyyy')
        Findings        = $Findings
        Sections        = $Sections
        CollectionNotes = $Notes
        ObjectCount     = $State.Count
    }
}
