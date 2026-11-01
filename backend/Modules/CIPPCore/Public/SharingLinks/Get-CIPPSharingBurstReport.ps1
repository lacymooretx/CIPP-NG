function Get-CIPPSharingBurstReport {
    <#
    .SYNOPSIS
        Tenant-wide check for lateral OneDrive/SharePoint phishing and mass external sharing, with the evidence and the ready-to-run cleanup parameters.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-13). Shared by the SharingBurst alert and the ListSharingBurst
        report. Detection only: nothing is changed in the tenant.

        1. Search-UnifiedAuditLog (Search-CIPPBecAuditLog: paged, time-bisected, completeness reported) for the
           sharing operations over the lookback, tenant-wide. This is the synchronous search the BEC check already
           runs, so it needs no new permission, creates no Purview search objects and does not compete with the
           audit-log webhook pipeline for the tenant's ~10 concurrent Graph audit queries.
        2. Get-CIPPSharingBurstFindings: UserBurst and FileSpread.
        3. For each account found - and each account that created anyone/company/secure links, up to
           MaxSendChecks - its own sent-mail spread against its baseline (Measure-CIPPSendSpread over message trace).
           A link-creating account whose sent mail spiked is raised as LinkMailBlast even below the sharing
           threshold: an "anyone" link mailed out is the same campaign without sharing invitations.
        4. For each finding's account, a risky or unfamiliar sign-in in the 24 hours before
           (Get-CIPPSharingBurstSignInContext).
        5. Remediation parameters for the existing CIPP actions - ExecRemoveSharingLink (from the sharing-links
           cache, or with -Resolve read live from Graph per item), ExecBulkRemoveSharingLinks per site and
           ExecSetOneDriveSharing for the account. They are offered, never run.
    .PARAMETER TenantFilter
        Tenant default domain.
    .PARAMETER LookbackHours
        Hours of sharing activity to analyse (default 24).
    .PARAMETER RecipientThreshold
        Distinct external recipients from one account within WindowMinutes (default 25).
    .PARAMETER WindowMinutes
        Burst window (default 60).
    .PARAMETER FileRecipientThreshold
        Distinct external recipients of one item over the lookback (default 25).
    .PARAMETER SendSpreadThreshold
        New external mail recipients in 24 h for the send-spread check (default 25).
    .PARAMETER AllowList
        Accounts never reported.
    .PARAMETER MaxSendChecks
        Accounts whose message trace is read per run (default 10).
    .PARAMETER Resolve
        Resolve link permission ids live from Graph for items not in the sharing-links cache (read only).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [ValidateRange(1, 168)][int]$LookbackHours = 24,
        [int]$RecipientThreshold = 25,
        [int]$WindowMinutes = 60,
        [int]$FileRecipientThreshold = 25,
        [int]$SendSpreadThreshold = 25,
        [string[]]$AllowList = @(),
        [int]$MaxSendChecks = 10,
        [switch]$Resolve
    )

    $Now = (Get-Date).ToUniversalTime()
    $Start = $Now.AddHours(-$LookbackHours)
    $Errors = [System.Collections.Generic.List[string]]::new()
    $SharingOps = @('SharingInvitationCreated', 'AddedToSecureLink', 'SecureLinkCreated', 'SecureLinkUpdated', 'AnonymousLinkCreated', 'AnonymousLinkUpdated', 'CompanyLinkCreated', 'SharingSet')

    $Search = Search-CIPPBecAuditLog -TenantFilter $TenantFilter -StartDate $Start -EndDate $Now -Operations $SharingOps -MaxPages 20
    $Events = @(ConvertTo-CIPPSharingEvent -Records @($Search.Records))
    $Accepted = @()
    if ($Events.Count -gt 0) {
        $Accepted = @(try { (New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-AcceptedDomain') | ForEach-Object { ([string]$_.DomainName).ToLowerInvariant() } | Where-Object { $_ } } catch { $Errors.Add("Accepted domains unavailable, recipients typed Guest count as external: $($_.Exception.Message)"); @() })
    }

    $Findings = [System.Collections.Generic.List[object]]::new()
    foreach ($F in @(Get-CIPPSharingBurstFindings -Events $Events -AcceptedDomains $Accepted -RecipientThreshold $RecipientThreshold -WindowMinutes $WindowMinutes -FileRecipientThreshold $FileRecipientThreshold -AllowList $AllowList)) {
        $Findings.Add($F)
    }

    # Send spread: finding accounts first, then link creators.
    $Allowed = @($AllowList | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
    $SendTargets = [System.Collections.Generic.List[string]]::new()
    foreach ($Upn in @($Findings | ForEach-Object { $_.Sharers } | Where-Object { $_ -and $_.Contains('@') })) { if (-not $SendTargets.Contains($Upn)) { $SendTargets.Add($Upn) } }
    $LinkCreators = @($Events | Where-Object { [string]$_.Operation -match 'LinkCreated|LinkUpdated' } | ForEach-Object { ([string]$_.UserKey).ToLowerInvariant() } | Where-Object { $_ -and $_.Contains('@') -and $Allowed -notcontains $_ } | Select-Object -Unique)
    foreach ($Upn in $LinkCreators) { if (-not $SendTargets.Contains($Upn)) { $SendTargets.Add($Upn) } }
    $Spread = @{}
    foreach ($Upn in @($SendTargets | Select-Object -First $MaxSendChecks)) {
        try {
            $Trace = Get-CIPPBecMessageTrace -TenantFilter $TenantFilter -SenderAddress $Upn -StartDate $Now.AddDays(-8) -EndDate $Now
            $Spread[$Upn] = Measure-CIPPSendSpread -Rows @($Trace.Rows) -Now $Now -AcceptedDomains $Accepted -MinNewRecipients $SendSpreadThreshold
        } catch {
            $Errors.Add("Message trace failed for $($Upn): $($_.Exception.Message)")
        }
    }
    if ($SendTargets.Count -gt $MaxSendChecks) { $Errors.Add("Send spread checked for the first $MaxSendChecks of $($SendTargets.Count) accounts.") }

    foreach ($Upn in $LinkCreators) {
        if (-not $Spread[$Upn].Flagged) { continue }
        if (@($Findings | Where-Object { $_.Sharers -contains $Upn }).Count -gt 0) { continue }
        $Set = @($Events | Where-Object { ([string]$_.UserKey).ToLowerInvariant() -eq $Upn -and [string]$_.Operation -match 'LinkCreated|LinkUpdated' } | Sort-Object { [datetime]$_.Date })
        $Files = @($Set | Group-Object { [string]$_.ItemUrl } | ForEach-Object { [pscustomobject]@{ ItemUrl = $_.Group[0].ItemUrl; FileName = $_.Group[0].FileName; Extension = ([string]$_.Group[0].AuditData.SourceFileExtension).ToLowerInvariant(); SiteUrl = [string]$_.Group[0].AuditData.SiteUrl; Recipients = 0 } })
        $Findings.Add([pscustomobject]@{
                Type               = 'LinkMailBlast'
                Account            = $Upn
                Sharers            = @($Upn)
                WindowStart        = ([datetime]$Set[0].Date).ToUniversalTime()
                WindowEnd          = ([datetime]$Set[-1].Date).ToUniversalTime()
                ExternalRecipients = $Spread[$Upn].NewExternalRecipients
                RecipientSample    = @($Spread[$Upn].NewRecipientSample)
                RecipientDomains   = @()
                Files              = $Files
                LureFile           = [bool](@($Files | Where-Object { $_.Extension -in @('one', 'onepkg', 'onetoc2', 'pdf', 'htm', 'html', 'shtml', 'svg', 'url', 'eml') }).Count -gt 0)
                LinksCreated       = $Set.Count
                AnonymousLinks     = @($Set | Where-Object { $_.Operation -like 'AnonymousLink*' }).Count
                SiteUrls           = @($Files.SiteUrl | Where-Object { $_ } | Select-Object -Unique)
                ClientIPs          = @($Set.ClientIP | Where-Object { $_ } | Select-Object -Unique)
                Events             = $Set.Count
            })
    }

    # The sharing-links cache supplies drive/item/permission ids without a Graph call.
    $CacheByItem = @{}
    if ($Findings.Count -gt 0) {
        try {
            foreach ($Link in @(Get-CIPPSharingLinks -TenantFilter $TenantFilter)) {
                if (-not $Link.itemUrl -or $Link.classification -notin @('Anonymous', 'External')) { continue }
                $Key = ([uri]::UnescapeDataString([string]$Link.itemUrl)).Trim().TrimEnd('/').ToLowerInvariant()
                if (-not $CacheByItem.ContainsKey($Key)) { $CacheByItem[$Key] = [System.Collections.Generic.List[object]]::new() }
                $CacheByItem[$Key].Add($Link)
            }
        } catch {
            $Errors.Add("Sharing-links cache unavailable: $($_.Exception.Message)")
        }
    }
    $ToShareId = { param($Url) 'u!' + ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$Url)).TrimEnd('=').Replace('/', '_').Replace('+', '-')) }

    $Rows = foreach ($F in $Findings) {
        $Account = [string]@($F.Sharers)[0]
        $Severity = 'Medium'
        $SendSpread = $Spread[$Account]
        $SignIn = $null
        if ($Account -and $Account.Contains('@')) {
            try { $SignIn = Get-CIPPSharingBurstSignInContext -TenantFilter $TenantFilter -UserPrincipalName $Account -Before $F.WindowStart } catch { $Errors.Add("Sign-in context failed for $($Account): $($_.Exception.Message)") }
        }
        if ($F.LureFile -or $SignIn.Notable -or $SendSpread.Flagged -or $F.Type -eq 'LinkMailBlast' -or $F.ExternalRecipients -ge (2 * $RecipientThreshold)) { $Severity = 'High' }

        # Remediation parameter sets for existing actions. Offered, never run.
        $Actions = [System.Collections.Generic.List[object]]::new()
        $Unresolved = [System.Collections.Generic.List[string]]::new()
        foreach ($File in @($F.Files | Where-Object { $_.ItemUrl } | Select-Object -First 25)) {
            $Key = ([uri]::UnescapeDataString([string]$File.ItemUrl)).Trim().TrimEnd('/').ToLowerInvariant()
            $Cached = @($CacheByItem[$Key])
            if ($Cached.Count -gt 0 -and $Cached[0]) {
                foreach ($Link in $Cached) {
                    $Actions.Add([pscustomobject]@{ Action = 'ExecRemoveSharingLink'; Source = 'sharing-links cache'; Body = [ordered]@{ tenantFilter = $TenantFilter; DriveId = $Link.driveId; ItemId = $Link.itemId; PermissionId = $Link.permissionId; FileName = $Link.fileName; CacheId = $Link.id } })
                }
            } elseif ($Resolve) {
                try {
                    $Item = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/shares/$(& $ToShareId $File.ItemUrl)/driveItem?`$select=id,name,parentReference&`$expand=permissions" -tenantid $TenantFilter -AsApp $true -noPagination $true -ErrorAction Stop
                    foreach ($Perm in @($Item.permissions | Where-Object { $_.link -and -not $_.inheritedFrom })) {
                        $Actions.Add([pscustomobject]@{ Action = 'ExecRemoveSharingLink'; Source = "live ($($Perm.link.scope) link)"; Body = [ordered]@{ tenantFilter = $TenantFilter; DriveId = $Item.parentReference.driveId; ItemId = $Item.id; PermissionId = $Perm.id; FileName = $Item.name } })
                    }
                    # Direct invitations to outsiders are permissions without a link, granted to the recipient.
                    foreach ($Perm in @($Item.permissions | Where-Object { -not $_.link -and -not $_.inheritedFrom -and ($_.grantedToV2.user.email ?? $_.invitation.email) })) {
                        $Actions.Add([pscustomobject]@{ Action = 'ExecRemoveSharingLink'; Source = "live (invitation to $($Perm.grantedToV2.user.email ?? $Perm.invitation.email))"; Body = [ordered]@{ tenantFilter = $TenantFilter; DriveId = $Item.parentReference.driveId; ItemId = $Item.id; PermissionId = $Perm.id; FileName = $Item.name } })
                    }
                } catch {
                    $Unresolved.Add([string]$File.ItemUrl)
                }
            } else {
                $Unresolved.Add([string]$File.ItemUrl)
            }
        }
        foreach ($Site in @($F.SiteUrls | Select-Object -First 5)) {
            $Actions.Add([pscustomobject]@{ Action = 'ExecBulkRemoveSharingLinks'; Source = 'revokes cached anonymous and external links on the whole site'; Body = [ordered]@{ tenantFilter = $TenantFilter; SiteUrl = $Site; Scope = 'External' } })
        }
        if ($Account -and $Account.Contains('@')) {
            $Actions.Add([pscustomobject]@{ Action = 'ExecSetOneDriveSharing'; Source = "stops new external sharing from $Account's OneDrive"; Body = [ordered]@{ tenantFilter = $TenantFilter; UPN = $Account; SharingCapability = 'Disabled' } })
        }

        $Central = try { [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { $null }
        $When = {
            param($Value)
            if (-not $Value) { return '' }
            $Utc = ([datetime]$Value).ToUniversalTime()
            if ($Central) {
                $Local = [System.TimeZoneInfo]::ConvertTimeFromUtc($Utc, $Central)
                return "$($Local.ToString('yyyy-MM-dd HH:mm')) $(if ($Central.IsDaylightSavingTime($Local)) { 'CDT' } else { 'CST' }) ($($Utc.ToString('HH:mm')) UTC)"
            }
            "$($Utc.ToString('yyyy-MM-dd HH:mm')) UTC"
        }
        $DetectionText = switch ($F.Type) {
            'UserBurst' { "$Account shared with $($F.ExternalRecipients) distinct external recipients within $WindowMinutes minutes" + $(if ($F.FileTotalRecipients) { " (one file reached $($F.FileTotalRecipients) over the window)" }) }
            'FileSpread' { "One item reached $($F.ExternalRecipients) distinct external recipients over $LookbackHours h (shared by $($F.Account))" }
            'LinkMailBlast' { "$Account created $($F.LinksCreated) sharing link(s) and then mailed $($F.ExternalRecipients) new external recipients" }
        }
        $IdKey = switch ($F.Type) {
            'FileSpread' {
                $Sha = [System.Security.Cryptography.SHA256]::Create()
                try { $Hash = (-join ($Sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(([string]@($F.Files)[0].ItemUrl).ToLowerInvariant())) | Select-Object -First 8 | ForEach-Object { $_.ToString('x2') })) } finally { $Sha.Dispose() }
                $Hash
            }
            default { $Account }
        }
        $ActionText = @($Actions | ForEach-Object { "$($_.Action) $(ConvertTo-Json -InputObject $_.Body -Compress)" }) + @(if ($Unresolved.Count -gt 0) { "ExecRemoveSharingLink: $($Unresolved.Count) item(s) not in the sharing-links cache; get their PermissionIds from ListSharingBurst?tenantFilter=$TenantFilter&resolve=true" })

        [pscustomobject]@{
            Id                 = "$($F.Type)|$($IdKey.ToLowerInvariant())|$(([datetime]$F.WindowStart).ToUniversalTime().ToString('yyyyMMdd'))"
            Severity           = $Severity
            Detection          = $F.Type
            Account            = $F.Account
            Detail             = $DetectionText
            Files              = (@($F.Files | Select-Object -First 5 | ForEach-Object { "$($_.FileName) ($($_.Recipients) external)" }) -join '; ')
            LureFile           = [bool]$F.LureFile
            ExternalRecipients = $F.ExternalRecipients
            RecipientSample    = (@($F.RecipientSample) -join ', ')
            RecipientDomains   = (@($F.RecipientDomains) -join ', ')
            LinksCreated       = $F.LinksCreated
            AnonymousLinks     = $F.AnonymousLinks
            FirstShared        = & $When $F.WindowStart
            LastShared         = & $When $F.WindowEnd
            IPs                = (@($F.ClientIPs | Select-Object -First 5) -join ', ')
            PrecedingSignIn    = if ($SignIn) { $SignIn.Summary } else { 'Not checked' }
            SendSpread         = if ($SendSpread) { $SendSpread.Summary + $(if ($SendSpread.Flagged) { ' - SPIKE' }) } else { 'Not checked' }
            'Next step'        = 'Detection only, nothing was changed. Confirm with the user by phone. If they did not share this: revoke sessions, reset the password, run the CIPP compromise (BEC) check, then remove the links with the ready actions below and warn the recipients.'
            ReadyActions       = ($ActionText -join ' | ')
            Remediation        = $Actions.ToArray()
            Tenant             = $TenantFilter
        }
    }

    [pscustomobject]@{
        Findings       = @($Rows)
        EventsAnalysed = $Events.Count
        Complete       = [bool]$Search.Complete
        Cap            = $Search.Cap
        Window         = [pscustomobject]@{ Start = $Start.ToString('o'); End = $Now.ToString('o') }
        Errors         = $Errors.ToArray()
    }
}
