function Get-CIPPSharingBurstFindings {
    <#
    .SYNOPSIS
        Finds mass external sharing in OneDrive/SharePoint sharing events: one account sharing with many outsiders fast, or one file reaching many outsiders over the window.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-13). Pure function over sharing events in the shape Push-BECRun stores
        as SharingChanges (Operation, UserKey, Date, FileName, ItemUrl, Target, TargetType, ClientIP, AuditData);
        ConvertTo-CIPPSharingEvent builds that shape from Search-CIPPBecAuditLog records. Used by the SharingBurst
        alert, the ListSharingBurst report and the BEC check.

        The pattern is lateral phishing from a compromised account: the attacker uploads a OneNote/PDF lure to the
        victim's OneDrive and shares it with everyone in the victim's address book. The events come from Microsoft
        data-centre addresses, so the IP says nothing; the recipient count does.

        Two detections:
          UserBurst   one account adds at least RecipientThreshold distinct EXTERNAL recipients within any
                      WindowMinutes-long window (two-pointer sliding window, so a burst straddling an hour boundary
                      is still one burst). The earliest qualifying window is reported, which keeps the finding stable
                      as later events arrive.
          FileSpread  one item reaches at least FileRecipientThreshold distinct external recipients across all the
                      events given (the whole lookback), even when spaced out. Folded into the sharer's UserBurst when
                      a single account did it all and already has one, so the same campaign is not raised twice.

        A recipient is a TargetUserOrGroupName that is an address. It is external when its domain is not one of
        AcceptedDomains, or - with no accepted domains given - when Entra typed it as a Guest. SharePoint groups
        (SharingLinks.*, Limited Access System Group) are skipped: they are the link's plumbing, not people.
        Anonymous ("anyone"), company and secure-link creations carry no recipient; they are counted per finding.
    .PARAMETER Events
        Sharing events (SharingChanges shape).
    .PARAMETER AcceptedDomains
        The tenant's accepted domains, lower case.
    .PARAMETER RecipientThreshold
        Distinct external recipients from one account within WindowMinutes (default 25).
    .PARAMETER WindowMinutes
        Burst window (default 60).
    .PARAMETER FileRecipientThreshold
        Distinct external recipients of one item across all events (default 25).
    .PARAMETER AllowList
        Accounts (UPN, lower case or not) never reported, e.g. a marketing mailbox that shares on purpose.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [object[]]$Events = @(),
        [string[]]$AcceptedDomains = @(),
        [int]$RecipientThreshold = 25,
        [int]$WindowMinutes = 60,
        [int]$FileRecipientThreshold = 25,
        [string[]]$AllowList = @()
    )

    $Accepted = @($AcceptedDomains | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $Allowed = @($AllowList | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
    $LureExtensions = @('one', 'onepkg', 'onetoc2', 'pdf', 'htm', 'html', 'shtml', 'svg', 'url', 'eml')
    $LinkOps = @('AnonymousLinkCreated', 'AnonymousLinkUpdated', 'CompanyLinkCreated', 'SecureLinkCreated', 'SecureLinkUpdated')

    $Normalize = {
        param($Url)
        if (-not $Url) { return '' }
        $Text = [string]$Url
        try { $Text = [uri]::UnescapeDataString($Text) } catch { $null = $_ }
        $Text.Trim().TrimEnd('/').ToLowerInvariant()
    }
    $ExtensionOf = {
        param($Event)
        $Ext = [string]$Event.AuditData.SourceFileExtension
        if (-not $Ext) {
            $Name = [string]($Event.FileName ?? $Event.AuditData.SourceFileName)
            if ($Name -and $Name.Contains('.')) { $Ext = $Name.Substring($Name.LastIndexOf('.') + 1) }
        }
        $Ext.TrimStart('.').ToLowerInvariant()
    }

    # One row per event with what the detections need.
    $Rows = foreach ($Event in @($Events | Where-Object { $_ })) {
        $User = ([string]($Event.UserKey ?? $Event.AuditData.UserId)).Trim().ToLowerInvariant()
        if (-not $User -or $Allowed -contains $User) { continue }
        $When = try { ([datetime]($Event.Date ?? $Event.AuditData.CreationTime)).ToUniversalTime() } catch { $null }
        if (-not $When) { continue }
        $Target = ([string]($Event.Target ?? $Event.AuditData.TargetUserOrGroupName)).Trim()
        $TargetType = [string]($Event.TargetType ?? $Event.AuditData.TargetUserOrGroupType)
        $Recipient = $null
        $External = $false
        if ($Target -and $Target.Contains('@') -and $Target -notmatch '^(SharingLinks\.|Limited Access System Group)' -and $TargetType -notin @('SharePointGroup', 'SecurityGroup')) {
            $Recipient = $Target.ToLowerInvariant()
            $Domain = ($Recipient -split '@')[-1]
            $External = if ($Accepted.Count -gt 0) { $Accepted -notcontains $Domain } else { $TargetType -eq 'Guest' }
        }
        $ItemUrl = [string]($Event.ItemUrl ?? $Event.AuditData.ObjectId)
        [pscustomobject]@{
            User      = $User
            When      = $When
            Operation = [string]$Event.Operation
            Recipient = $Recipient
            External  = [bool]$External
            ItemUrl   = $ItemUrl
            ItemKey   = & $Normalize $ItemUrl
            FileName  = [string]($Event.FileName ?? $Event.AuditData.SourceFileName)
            Extension = & $ExtensionOf $Event
            SiteUrl   = [string]$Event.AuditData.SiteUrl
            ClientIP  = [string]$Event.ClientIP
            IsLink    = $LinkOps -contains [string]$Event.Operation
        }
    }
    $Rows = @($Rows | Sort-Object When)

    $Summarise = {
        param($Set, $Type, $Account, $Start, $End, $RecipientList)
        $Files = @($Set | Where-Object { $_.ItemKey } | Group-Object ItemKey | ForEach-Object {
                $First = $_.Group[0]
                [pscustomobject]@{ ItemUrl = $First.ItemUrl; FileName = $First.FileName; Extension = $First.Extension; SiteUrl = $First.SiteUrl; Recipients = @($_.Group | Where-Object { $_.External -and $_.Recipient } | ForEach-Object Recipient | Select-Object -Unique).Count }
            } | Sort-Object Recipients -Descending)
        $Recipients = @($RecipientList | Select-Object -Unique)
        [pscustomobject]@{
            Type               = $Type
            Account            = $Account
            Sharers            = @($Set.User | Select-Object -Unique)
            WindowStart        = $Start
            WindowEnd          = $End
            ExternalRecipients = $Recipients.Count
            RecipientSample    = @($Recipients | Select-Object -First 10)
            RecipientDomains   = @($Recipients | ForEach-Object { ($_ -split '@')[-1] } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) ($($_.Count))" })
            Files              = $Files
            LureFile           = [bool](@($Files | Where-Object { $LureExtensions -contains $_.Extension }).Count -gt 0)
            LinksCreated       = @($Set | Where-Object IsLink).Count
            AnonymousLinks     = @($Set | Where-Object { $_.Operation -like 'AnonymousLink*' }).Count
            SiteUrls           = @($Set.SiteUrl | Where-Object { $_ } | Select-Object -Unique)
            ClientIPs          = @($Set.ClientIP | Where-Object { $_ } | Select-Object -Unique)
            Events             = $Set.Count
        }
    }

    $Findings = [System.Collections.Generic.List[object]]::new()

    # UserBurst: two-pointer window over each account's external-recipient events.
    $Span = [timespan]::FromMinutes([Math]::Max(1, $WindowMinutes))
    foreach ($UserGroup in ($Rows | Group-Object User)) {
        $Ext = @($UserGroup.Group | Where-Object { $_.External -and $_.Recipient })
        if ($Ext.Count -lt $RecipientThreshold) { continue }
        $Counts = @{}
        $Left = 0
        $Hit = $null
        for ($Right = 0; $Right -lt $Ext.Count; $Right++) {
            $Counts[$Ext[$Right].Recipient] = 1 + [int]$Counts[$Ext[$Right].Recipient]
            while ($Ext[$Right].When - $Ext[$Left].When -gt $Span) {
                $Key = $Ext[$Left].Recipient
                $Counts[$Key] = [int]$Counts[$Key] - 1
                if ($Counts[$Key] -le 0) { $Counts.Remove($Key) }
                $Left++
            }
            if ($Counts.Count -ge $RecipientThreshold) { $Hit = @{ Left = $Left; Right = $Right }; break }
        }
        if (-not $Hit) { continue }
        $Start = $Ext[$Hit.Left].When
        $End = $Start + $Span
        # Everything the account did in the burst window, links included.
        $Set = @($UserGroup.Group | Where-Object { $_.When -ge $Start -and $_.When -le $End })
        $Recipients = @($Set | Where-Object { $_.External -and $_.Recipient } | ForEach-Object Recipient)
        $Findings.Add((& $Summarise $Set 'UserBurst' $UserGroup.Name $Start $End $Recipients))
    }

    # FileSpread: one item, many outsiders, any pace.
    foreach ($ItemGroup in ($Rows | Where-Object { $_.ItemKey } | Group-Object ItemKey)) {
        $Recipients = @($ItemGroup.Group | Where-Object { $_.External -and $_.Recipient } | ForEach-Object Recipient | Select-Object -Unique)
        if ($Recipients.Count -lt $FileRecipientThreshold) { continue }
        $Sharers = @($ItemGroup.Group.User | Select-Object -Unique)
        if ($Sharers.Count -eq 1) {
            $Burst = $Findings | Where-Object { $_.Type -eq 'UserBurst' -and $_.Account -eq $Sharers[0] -and @($_.Files.ItemUrl | ForEach-Object { & $Normalize $_ }) -contains $ItemGroup.Name } | Select-Object -First 1
            if ($Burst) {
                $Burst | Add-Member -NotePropertyName 'FileTotalRecipients' -NotePropertyValue $Recipients.Count -Force
                continue
            }
        }
        $Set = @($ItemGroup.Group)
        $Findings.Add((& $Summarise $Set 'FileSpread' ($Sharers -join ', ') $Set[0].When $Set[-1].When $Recipients))
    }

    $Findings.ToArray()
}
