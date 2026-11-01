# Aspendora fork (Vikunja CIPP-13): lateral OneDrive/SharePoint phishing - the pure detection and send-spread functions.
# Events use the SharingChanges shape Push-BECRun stores; field names follow the SharePoint sharing audit schema
# (TargetUserOrGroupName / TargetUserOrGroupType, SourceFileName / SourceFileExtension, SiteUrl, ObjectId).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/SharingLinks/Get-CIPPSharingBurstFindings.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/SharingLinks/Measure-CIPPSendSpread.ps1')

    $script:T0 = [datetime]::new(2026, 10, 31, 15, 0, 0, [System.DateTimeKind]::Utc)
    $script:Lure = 'https://contoso-my.sharepoint.com/personal/victim_contoso_com/Documents/Invoice%20Review.one'
    function New-Share {
        param([string]$User = 'victim@contoso.com', [int]$Minute, [string]$Recipient, [string]$Type = 'Guest', [string]$Url = $script:Lure, [string]$Operation = 'AddedToSecureLink')
        $Name = [uri]::UnescapeDataString(($Url -split '/')[-1])
        [pscustomobject]@{
            Operation  = $Operation
            UserKey    = $User
            Date       = $script:T0.AddMinutes($Minute).ToString('o')
            FileName   = $Name
            ItemUrl    = $Url
            Target     = $Recipient
            TargetType = $Type
            ClientIP   = '52.108.0.10'
            AuditData  = [pscustomobject]@{ SiteUrl = 'https://contoso-my.sharepoint.com/personal/victim_contoso_com/'; SourceFileExtension = ($Name -split '\.')[-1] }
        }
    }
    function New-Burst {
        param([int]$Count, [int]$SpacingMinutes = 1, [int]$Offset = 0, [string]$Url = $script:Lure, [string]$User = 'victim@contoso.com')
        foreach ($I in 1..$Count) { New-Share -User $User -Minute ($Offset + $I * $SpacingMinutes) -Recipient "person$I@partner$($I % 4).example" -Url $Url }
    }
}

Describe 'Get-CIPPSharingBurstFindings' {
    It 'raises a UserBurst when one account reaches the recipient threshold within the window' {
        $F = @(Get-CIPPSharingBurstFindings -Events @(New-Burst -Count 30) -AcceptedDomains @('contoso.com'))
        $F.Count | Should -Be 1
        $F[0].Type | Should -Be 'UserBurst'
        $F[0].Account | Should -Be 'victim@contoso.com'
        $F[0].ExternalRecipients | Should -Be 30
        $F[0].LureFile | Should -BeTrue
        $F[0].Files[0].FileName | Should -Be 'Invoice Review.one'
        $F[0].RecipientDomains.Count | Should -BeGreaterThan 0
    }

    It 'stays quiet below the threshold' {
        @(Get-CIPPSharingBurstFindings -Events @(New-Burst -Count 24) -AcceptedDomains @('contoso.com')).Count | Should -Be 0
    }

    It 'finds a burst that straddles a clock hour (sliding window, not hourly buckets)' {
        # 30 shares between 15:45 and 16:15: neither clock hour holds 25.
        $Events = @(New-Burst -Count 30 -Offset 44)
        $F = @(Get-CIPPSharingBurstFindings -Events $Events -AcceptedDomains @('contoso.com'))
        @($F | Where-Object Type -EQ 'UserBurst').Count | Should -Be 1
    }

    It 'reports the earliest qualifying window so the finding is stable as events arrive' {
        $First = @(Get-CIPPSharingBurstFindings -Events @(New-Burst -Count 26) -AcceptedDomains @('contoso.com'))[0]
        $Later = @(Get-CIPPSharingBurstFindings -Events @(New-Burst -Count 40) -AcceptedDomains @('contoso.com'))[0]
        $Later.WindowStart | Should -Be $First.WindowStart
    }

    It 'does not count internal recipients, SharePoint link groups, or the same recipient twice' {
        $Events = @(New-Burst -Count 20) +
            @(1..10 | ForEach-Object { New-Share -Minute (30 + $_) -Recipient "colleague$_@contoso.com" -Type 'Member' }) +
            @(1..10 | ForEach-Object { New-Share -Minute (40 + $_) -Recipient 'SharingLinks.abc.Flexible.def' -Type 'SharePointGroup' -Operation 'SharingSet' }) +
            @(1..10 | ForEach-Object { New-Share -Minute (50 + $_) -Recipient 'person1@partner1.example' -Operation 'SharingInvitationCreated' })
        @(Get-CIPPSharingBurstFindings -Events $Events -AcceptedDomains @('contoso.com')).Count | Should -Be 0
    }

    It 'falls back to the Guest type when accepted domains are unknown' {
        $Events = @(1..30 | ForEach-Object { New-Share -Minute $_ -Recipient "colleague$_@contoso.com" -Type 'Member' })
        @(Get-CIPPSharingBurstFindings -Events $Events).Count | Should -Be 0
        @(Get-CIPPSharingBurstFindings -Events @(New-Burst -Count 30)).Count | Should -Be 1
    }

    It 'raises a FileSpread for one file shared to many outsiders over the day, even when spaced out' {
        # One share every 40 minutes: never 25 in an hour, but 30 recipients over 20 hours, from two people.
        $Events = @(1..30 | ForEach-Object { New-Share -User $(if ($_ % 2) { 'a@contoso.com' } else { 'b@contoso.com' }) -Minute ($_ * 40) -Recipient "person$_@outside.example" })
        $F = @(Get-CIPPSharingBurstFindings -Events $Events -AcceptedDomains @('contoso.com'))
        $F.Count | Should -Be 1
        $F[0].Type | Should -Be 'FileSpread'
        $F[0].ExternalRecipients | Should -Be 30
        $F[0].Sharers.Count | Should -Be 2
    }

    It 'folds a FileSpread into the sharer''s own UserBurst instead of raising the campaign twice' {
        $Events = @(New-Burst -Count 30) + @(31..40 | ForEach-Object { New-Share -Minute (300 + $_) -Recipient "late$_@outside.example" })
        $F = @(Get-CIPPSharingBurstFindings -Events $Events -AcceptedDomains @('contoso.com'))
        $F.Count | Should -Be 1
        $F[0].Type | Should -Be 'UserBurst'
        $F[0].FileTotalRecipients | Should -Be 40
    }

    It 'skips allow-listed accounts' {
        @(Get-CIPPSharingBurstFindings -Events @(New-Burst -Count 30) -AcceptedDomains @('contoso.com') -AllowList @('Victim@Contoso.com')).Count | Should -Be 0
    }

    It 'honours custom thresholds and counts link creations' {
        $Events = @(New-Burst -Count 6) + @(New-Share -Minute 3 -Recipient $null -Type '' -Operation 'AnonymousLinkCreated')
        $F = @(Get-CIPPSharingBurstFindings -Events $Events -AcceptedDomains @('contoso.com') -RecipientThreshold 5 -FileRecipientThreshold 100)
        $F.Count | Should -Be 1
        $F[0].AnonymousLinks | Should -Be 1
        $F[0].LinksCreated | Should -Be 1
    }

    It 'flags only lure file types as lures' {
        $Doc = 'https://contoso.sharepoint.com/sites/Sales/Shared Documents/Q3 plan.xlsx'
        $F = @(Get-CIPPSharingBurstFindings -Events @(New-Burst -Count 30 -Url $Doc) -AcceptedDomains @('contoso.com'))
        $F[0].LureFile | Should -BeFalse
    }
}

Describe 'Measure-CIPPSendSpread' {
    BeforeAll {
        $script:Now = [datetime]::new(2026, 10, 31, 18, 0, 0, [System.DateTimeKind]::Utc)
        function New-Trace { param([string]$To, [double]$HoursAgo) [pscustomobject]@{ RecipientAddress = $To; Received = $script:Now.AddHours(-$HoursAgo).ToString('o') } }
        # A normal week: the same 5 outside contacts every day, plus colleagues.
        $script:Week = foreach ($Day in 1..7) { foreach ($I in 1..5) { New-Trace "client$I@customer.example" (24 * $Day + 2) }; New-Trace 'boss@contoso.com' (24 * $Day + 3) }
    }

    It 'flags a jump in new external recipients against the account''s own baseline' {
        $Blast = 1..40 | ForEach-Object { New-Trace "contact$_@elsewhere$($_ % 7).example" 2 }
        $S = Measure-CIPPSendSpread -Rows @($script:Week + $Blast) -Now $script:Now -AcceptedDomains @('contoso.com')
        $S.Flagged | Should -BeTrue
        $S.NewExternalRecipients | Should -Be 40
        $S.BaselineDailyAverage | Should -Be 5
    }

    It 'does not flag a normal day' {
        $Day = 1..5 | ForEach-Object { New-Trace "client$_@customer.example" 2 }
        (Measure-CIPPSendSpread -Rows @($script:Week + $Day) -Now $script:Now -AcceptedDomains @('contoso.com')).Flagged | Should -BeFalse
    }

    It 'does not flag a busy sender whose volume is normal for them' {
        $Busy = foreach ($Day in 0..7) { foreach ($I in 1..60) { New-Trace "lead$($Day)x$I@prospects.example" (24 * $Day + 2) } }
        (Measure-CIPPSendSpread -Rows @($Busy) -Now $script:Now -AcceptedDomains @('contoso.com')).Flagged | Should -BeFalse
    }

    It 'ignores internal recipients' {
        $Internal = 1..50 | ForEach-Object { New-Trace "staff$_@contoso.com" 2 }
        (Measure-CIPPSendSpread -Rows @($script:Week + $Internal) -Now $script:Now -AcceptedDomains @('contoso.com')).ExternalRecipients24h | Should -Be 0
    }
}
