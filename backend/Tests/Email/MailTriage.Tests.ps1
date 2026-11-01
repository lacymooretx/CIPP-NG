# Aspendora fork (Vikunja CIPP-38): mail-not-received triage - step grading, Central time rendering,
# the collector's isolation of failing steps, and the ConnectWise note text.
BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    foreach ($F in 'ConvertTo-CIPPCentralTime', 'Resolve-CIPPMailTriageStep', 'Get-CIPPMessageTraceRange', 'Get-CIPPMailTriage', 'ConvertTo-CIPPMailTriageNote') {
        . (Join-Path $BackendRoot "Modules/CIPPCore/Public/MailTriage/$F.ps1")
    }
    function New-ExoRequest { param($tenantid, $cmdlet, $cmdParams, $Anchor, $useSystemMailbox) }
    function New-GraphGetRequest { param($uri, $tenantid, $AsApp, $noPagination) }
    function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = "$($Exception.Exception.Message)" } }

    $script:Ctx = @{ Recipient = 'amy@contoso.com'; Sender = 'bob@vendor.com'; AcceptedDomains = @('contoso.com') }
}

Describe 'ConvertTo-CIPPCentralTime' {
    It 'shows CDT in summer and CST in winter, with UTC alongside' {
        (ConvertTo-CIPPCentralTime -Value '2026-07-01T17:00:00Z').Display | Should -Be '2026-07-01 12:00 CDT (17:00 UTC)'
        (ConvertTo-CIPPCentralTime -Value '2026-12-01T17:00:00Z').Display | Should -Be '2026-12-01 11:00 CST (17:00 UTC)'
    }
    It 'spells out the UTC date when it is already the next day' {
        (ConvertTo-CIPPCentralTime -Value '2026-11-01T02:30:00Z').Display | Should -Be '2026-10-31 21:30 CDT (2026-11-01 02:30 UTC)'
    }
    It 'treats an unspecified DateTime as UTC and returns null for empty input' {
        (ConvertTo-CIPPCentralTime -Value ([datetime]::new(2026, 7, 1, 17, 0, 0))).Utc | Should -Be '2026-07-01T17:00:00Z'
        ConvertTo-CIPPCentralTime -Value $null | Should -BeNullOrEmpty
        ConvertTo-CIPPCentralTime -Value 'not a date' | Should -BeNullOrEmpty
    }
}

Describe 'Resolve-CIPPMailTriageStep' {
    Context 'ServiceHealth' {
        It 'flags an open Exchange incident or a mail-flow advisory, not an unrelated advisory' {
            $Notes = @{ id = 'EX1'; classification = 'advisory'; service = 'Exchange Online'; title = 'Users are unable to access Notes in Outlook on the web'; feature = 'OWA'; isResolved = $false }
            (Resolve-CIPPMailTriageStep -Key ServiceHealth -Data @{ Issues = @([pscustomobject]$Notes) } -Context $script:Ctx).Status | Should -Be 'OK'
            $Delay = @{ id = 'EX2'; classification = 'advisory'; service = 'Exchange Online'; title = 'Some users may experience mail delivery delays'; isResolved = $false }
            (Resolve-CIPPMailTriageStep -Key ServiceHealth -Data @{ Issues = @([pscustomobject]$Delay) } -Context $script:Ctx).Status | Should -Be 'Problem'
            $Inc = @{ id = 'EX3'; classification = 'incident'; service = 'Exchange Online'; title = 'Anything'; isResolved = $false }
            (Resolve-CIPPMailTriageStep -Key ServiceHealth -Data @{ Issues = @([pscustomobject]$Inc) } -Context $script:Ctx).Status | Should -Be 'Problem'
        }
    }

    Context 'MessageTrace' {
        It 'is a Problem with sender advice when nothing arrived from the named sender' {
            $R = Resolve-CIPPMailTriageStep -Key MessageTrace -Data @{ Rows = @() } -Context $script:Ctx
            $R.Status | Should -Be 'Problem'
            $R.Summary | Should -Match 'never handed it over'
        }
        It 'explains junk and quarantine statuses, and shows times in Central' {
            $Rows = @(
                [pscustomobject]@{ Received = '2026-10-30T15:00:00Z'; SenderAddress = 'bob@vendor.com'; RecipientAddress = 'amy@contoso.com'; Status = 'FilteredAsSpam'; Subject = 'Invoice' }
                [pscustomobject]@{ Received = '2026-10-30T14:00:00Z'; SenderAddress = 'bob@vendor.com'; RecipientAddress = 'amy@contoso.com'; Status = 'Delivered'; Subject = 'Hi' }
            )
            $R = Resolve-CIPPMailTriageStep -Key MessageTrace -Data @{ Rows = $Rows } -Context $script:Ctx
            $R.Status | Should -Be 'Problem'
            $R.Summary | Should -Match 'Junk Email folder'
            $R.Evidence[0].Received | Should -Be '2026-10-30 10:00 CDT (15:00 UTC)'
            $R.Evidence[0].ReceivedUtc | Should -Be '2026-10-30T15:00:00Z'
        }
        It 'is OK when everything was delivered' {
            $Rows = @([pscustomobject]@{ Received = '2026-10-30T14:00:00Z'; SenderAddress = 'bob@vendor.com'; RecipientAddress = 'amy@contoso.com'; Status = 'Delivered' })
            (Resolve-CIPPMailTriageStep -Key MessageTrace -Data @{ Rows = $Rows } -Context $script:Ctx).Status | Should -Be 'OK'
        }
    }

    Context 'Quarantine' {
        It 'counts only unreleased messages' {
            $Q = @(
                [pscustomobject]@{ ReceivedTime = '2026-10-30T14:00:00Z'; SenderAddress = 'bob@vendor.com'; Type = 'High Confidence Phish'; ReleaseStatus = 'NOTRELEASED' }
                [pscustomobject]@{ ReceivedTime = '2026-10-30T13:00:00Z'; SenderAddress = 'bob@vendor.com'; Type = 'Spam'; ReleaseStatus = 'RELEASED'; Released = $true }
            )
            $R = Resolve-CIPPMailTriageStep -Key Quarantine -Data @{ Messages = $Q } -Context $script:Ctx
            $R.Status | Should -Be 'Problem'
            $R.Summary | Should -Match '^1 unreleased'
            (Resolve-CIPPMailTriageStep -Key Quarantine -Data @{ Messages = @() } -Context $script:Ctx).Status | Should -Be 'OK'
        }
    }

    Context 'TransportRules' {
        It 'flags an enforced rule that names the sender domain and rejects, unless an exception applies' {
            $Rule = [pscustomobject]@{ Name = 'Block vendor'; State = 'Enabled'; Mode = 'Enforce'; Priority = 0; SenderDomainIs = @('vendor.com'); RejectMessageReasonText = 'no' }
            (Resolve-CIPPMailTriageStep -Key TransportRules -Data @{ Rules = @($Rule) } -Context $script:Ctx).Status | Should -Be 'Problem'
            $Excepted = [pscustomobject]@{ Name = 'Block vendor'; State = 'Enabled'; Mode = 'Enforce'; Priority = 0; SenderDomainIs = @('vendor.com'); ExceptIfSentTo = @('amy@contoso.com'); DeleteMessage = $true }
            (Resolve-CIPPMailTriageStep -Key TransportRules -Data @{ Rules = @($Excepted) } -Context $script:Ctx).Status | Should -Be 'OK'
        }
        It 'ignores disabled and audit-mode rules, and SCL -1 bypass rules' {
            $Rules = @(
                [pscustomobject]@{ Name = 'Off'; State = 'Disabled'; SenderDomainIs = @('vendor.com'); DeleteMessage = $true }
                [pscustomobject]@{ Name = 'Test'; State = 'Enabled'; Mode = 'Audit'; SenderDomainIs = @('vendor.com'); DeleteMessage = $true }
                [pscustomobject]@{ Name = 'Bypass'; State = 'Enabled'; Mode = 'Enforce'; SenderDomainIs = @('vendor.com'); SetSCL = '-1' }
            )
            (Resolve-CIPPMailTriageStep -Key TransportRules -Data @{ Rules = $Rules } -Context $script:Ctx).Status | Should -Be 'OK'
        }
        It 'lists broad delete rules (attachment blocks) as findings, not problems' {
            $Rule = [pscustomobject]@{ Name = 'RansomwareBlocking'; State = 'Enabled'; Mode = 'Enforce'; Priority = 7; DeleteMessage = $true; SentToScope = 'InOrganization' }
            $R = Resolve-CIPPMailTriageStep -Key TransportRules -Data @{ Rules = @($Rule) } -Context $script:Ctx
            $R.Status | Should -Be 'OK'
            $R.Findings[0] | Should -Match 'RansomwareBlocking'
        }
    }

    Context 'InboxRules' {
        It 'flags a rule that deletes this sender, and one that redirects everything' {
            $Del = [pscustomobject]@{ Name = 'Del'; Enabled = $true; From = @('"Bob" [SMTP:bob@vendor.com]'); DeleteMessage = $true; Description = 'If the message: received from Bob' }
            (Resolve-CIPPMailTriageStep -Key InboxRules -Data @{ Rules = @($Del) } -Context $script:Ctx).Status | Should -Be 'Problem'
            $All = [pscustomobject]@{ Name = 'x'; Enabled = $true; RedirectTo = @('evil@x.com'); Description = 'Take the following actions: redirect' }
            $R = Resolve-CIPPMailTriageStep -Key InboxRules -Data @{ Rules = @($All) } -Context @{ Recipient = 'amy@contoso.com' }
            $R.Status | Should -Be 'Problem'
            $R.Summary | Should -Match 'every message'
        }
        It 'matches FromAddressContainsWords against the sender' {
            $Move = [pscustomobject]@{ Name = 'Vendor'; Enabled = $true; FromAddressContainsWords = @('vendor.com'); MoveToFolder = 'Vendors'; Description = 'If the message: sender address contains vendor.com' }
            (Resolve-CIPPMailTriageStep -Key InboxRules -Data @{ Rules = @($Move) } -Context $script:Ctx).Status | Should -Be 'Problem'
        }
        It 'skips the Junk E-mail Rule, disabled rules and other senders' {
            $Rules = @(
                [pscustomobject]@{ Name = 'Junk E-mail Rule'; Enabled = $true; MoveToFolder = 'Junk' }
                [pscustomobject]@{ Name = 'Off'; Enabled = $false; DeleteMessage = $true; Description = 'Take the following actions: delete' }
                [pscustomobject]@{ Name = 'Other'; Enabled = $true; From = @('"Eve" [SMTP:eve@other.com]'); DeleteMessage = $true; Description = 'If the message: from Eve' }
            )
            (Resolve-CIPPMailTriageStep -Key InboxRules -Data @{ Rules = $Rules } -Context $script:Ctx).Status | Should -Be 'OK'
        }
    }

    Context 'Restrictions' {
        It 'flags accept-only lists, internal-only and forwarding without a copy' {
            $M = [pscustomobject]@{ AcceptMessagesOnlyFrom = @('Finance Team'); RequireSenderAuthenticationEnabled = $true; ForwardingSmtpAddress = 'smtp:x@gmail.com'; DeliverToMailboxAndForward = $false; MaxReceiveSize = '36 MB (37,748,736 bytes)' }
            $R = Resolve-CIPPMailTriageStep -Key Restrictions -Data @{ Recipient = $M } -Context $script:Ctx
            $R.Status | Should -Be 'Problem'
            $R.Summary | Should -Match 'only accepts mail from: Finance Team'
            $R.Summary | Should -Match 'external mail is rejected'
            $R.Summary | Should -Match 'does NOT keep a copy'
        }
        It 'is OK for an unrestricted mailbox, and does not call internal senders external' {
            $M = [pscustomobject]@{ RequireSenderAuthenticationEnabled = $true; MaxReceiveSize = '36 MB (37,748,736 bytes)' }
            (Resolve-CIPPMailTriageStep -Key Restrictions -Data @{ Recipient = $M } -Context @{ Recipient = 'amy@contoso.com'; Sender = 'carl@contoso.com'; AcceptedDomains = @('contoso.com') }).Status | Should -Be 'OK'
        }
    }

    Context 'Quota' {
        It 'flags a full and a nearly full mailbox from EXO size strings' {
            $Mbx = [pscustomobject]@{ ProhibitSendReceiveQuota = '50 GB (53,687,091,200 bytes)'; IssueWarningQuota = '49 GB (52,613,349,376 bytes)'; ArchiveStatus = 'Active' }
            $Full = [pscustomobject]@{ TotalItemSize = '50 GB (53,687,091,200 bytes)' }
            (Resolve-CIPPMailTriageStep -Key Quota -Data @{ Mailbox = $Mbx; Stats = $Full } -Context $script:Ctx).Summary | Should -Match 'is full'
            $Near = [pscustomobject]@{ TotalItemSize = '48 GB (51,539,607,552 bytes)' }
            (Resolve-CIPPMailTriageStep -Key Quota -Data @{ Mailbox = $Mbx; Stats = $Near } -Context $script:Ctx).Status | Should -Be 'Problem'
            $Ok = [pscustomobject]@{ TotalItemSize = '10 GB (10,737,418,240 bytes)' }
            $R = Resolve-CIPPMailTriageStep -Key Quota -Data @{ Mailbox = $Mbx; Stats = $Ok } -Context $script:Ctx
            $R.Status | Should -Be 'OK'
            $R.Evidence.PercentOfReceiveQuota | Should -Be 20
        }
        It 'is Unknown without statistics' {
            (Resolve-CIPPMailTriageStep -Key Quota -Data @{ Mailbox = $null; Stats = $null } -Context $script:Ctx).Status | Should -Be 'Unknown'
        }
    }

    Context 'SenderBlocks' {
        It 'matches TABL blocks by address, domain and *.TLD' {
            foreach ($V in 'bob@vendor.com', 'vendor.com', '*.com') {
                $R = Resolve-CIPPMailTriageStep -Key SenderBlocks -Data @{ TablSender = @([pscustomobject]@{ Value = $V; Action = 'Block' }); Junk = $null } -Context $script:Ctx
                $R.Status | Should -Be 'Problem' -Because "TABL entry '$V' covers bob@vendor.com"
            }
            (Resolve-CIPPMailTriageStep -Key SenderBlocks -Data @{ TablSender = @([pscustomobject]@{ Value = '*.xyz'; Action = 'Block' }) } -Context $script:Ctx).Status | Should -Be 'OK'
        }
        It 'flags the user''s own Blocked Senders and TrustedListsOnly' {
            $Junk = [pscustomobject]@{ Enabled = $true; BlockedSendersAndDomains = @('vendor.com'); TrustedSendersAndDomains = @(); TrustedListsOnly = $false }
            (Resolve-CIPPMailTriageStep -Key SenderBlocks -Data @{ TablSender = @(); Junk = $Junk } -Context $script:Ctx).Summary | Should -Match 'blocked .vendor.com. in Outlook'
            $Strict = [pscustomobject]@{ Enabled = $true; BlockedSendersAndDomains = @(); TrustedSendersAndDomains = @(); TrustedListsOnly = $true }
            (Resolve-CIPPMailTriageStep -Key SenderBlocks -Data @{ TablSender = @(); Junk = $Strict } -Context @{ Recipient = 'amy@contoso.com' }).Status | Should -Be 'Problem'
        }
    }

    Context 'SignIn' {
        It 'flags a disabled account and all-failed sign-ins' {
            (Resolve-CIPPMailTriageStep -Key SignIn -Data @{ User = [pscustomobject]@{ accountEnabled = $false } } -Context $script:Ctx).Status | Should -Be 'Problem'
            $Fail = 1..3 | ForEach-Object { [pscustomobject]@{ createdDateTime = '2026-10-30T14:00:00Z'; status = [pscustomobject]@{ errorCode = 50126; failureReason = 'Invalid password' } } }
            (Resolve-CIPPMailTriageStep -Key SignIn -Data @{ User = [pscustomobject]@{ accountEnabled = $true }; SignIns = $Fail } -Context $script:Ctx).Status | Should -Be 'Problem'
            $Ok = @([pscustomobject]@{ createdDateTime = '2026-10-30T14:00:00Z'; status = [pscustomobject]@{ errorCode = 0 } })
            (Resolve-CIPPMailTriageStep -Key SignIn -Data @{ User = [pscustomobject]@{ accountEnabled = $true; signInActivity = [pscustomobject]@{ lastSuccessfulSignInDateTime = [DateTime]::UtcNow.ToString('o') } }; SignIns = $Ok } -Context $script:Ctx).Status | Should -Be 'OK'
        }
    }
}

Describe 'Get-CIPPMailTriage' {
    BeforeEach {
        Mock New-GraphGetRequest { @() }
        Mock New-ExoRequest {
            switch ($cmdlet) {
                'Get-AcceptedDomain' { @([pscustomobject]@{ DomainName = 'contoso.com' }) }
                'Get-Mailbox' { [pscustomobject]@{ PrimarySmtpAddress = 'amy@contoso.com'; ArchiveStatus = 'None'; ProhibitSendReceiveQuota = '50 GB (53,687,091,200 bytes)' } }
                'Get-MailboxStatistics' { [pscustomobject]@{ TotalItemSize = '1 GB (1,073,741,824 bytes)' } }
                'Get-TransportRule' { throw 'transport boom' }
                default { @() }
            }
        }
    }

    It 'runs all nine steps in order, isolates a failing step as Unknown, and only reads' {
        $B = Get-CIPPMailTriage -TenantFilter 'contoso.com' -Recipient 'amy@contoso.com' -Sender 'bob@vendor.com'
        $B.Steps.Key | Should -Be @('ServiceHealth', 'MessageTrace', 'Quarantine', 'TransportRules', 'InboxRules', 'Restrictions', 'Quota', 'SenderBlocks', 'SignIn')
        ($B.Steps | Where-Object Key -EQ 'TransportRules').Status | Should -Be 'Unknown'
        ($B.Steps | Where-Object Key -EQ 'TransportRules').Summary | Should -Match 'transport boom'
        $B.Summary | Should -Match 'Could not check: Mail flow'
        Should -Invoke New-ExoRequest -ParameterFilter { $cmdlet -notmatch '^Get-' } -Times 0 -Exactly
        $B.WindowStart.Display | Should -Match ' C[DS]T \('
        $B.Hours | Should -Be 48
    }

    It 'asks Get-InboxRule for hidden rules and traces the primary address' {
        $null = Get-CIPPMailTriage -TenantFilter 'contoso.com' -Recipient 'Amy.Alias@contoso.com'
        Should -Invoke New-ExoRequest -ParameterFilter { $cmdlet -eq 'Get-InboxRule' -and $cmdParams.IncludeHidden -eq $true -and $cmdParams.Mailbox -eq 'amy@contoso.com' } -Times 1 -Exactly
        Should -Invoke New-ExoRequest -ParameterFilter { $cmdlet -eq 'Get-MessageTraceV2' -and $cmdParams.RecipientAddress -contains 'amy@contoso.com' } -Times 1
    }
}

Describe 'ConvertTo-CIPPMailTriageNote' {
    BeforeAll {
        $script:Bundle = [pscustomobject]@{
            Tenant = 'contoso.com'; Recipient = 'amy@contoso.com'; Sender = 'bob@vendor.com'; Hours = 48; Overall = 'Problem'
            Summary = '1 of 2 checks found a problem.'
            WindowStart = [pscustomobject]@{ Display = '2026-10-29 10:00 CDT (15:00 UTC)' }; WindowEnd = [pscustomobject]@{ Display = '2026-10-31 10:00 CDT (15:00 UTC)' }; GeneratedAt = [pscustomobject]@{ Display = '2026-10-31 10:00 CDT (15:00 UTC)' }
            Steps = @(
                [pscustomobject]@{ Title = 'Quarantine (admin view)'; Status = 'Problem'; Summary = '1 unreleased message in quarantine.'; Findings = @('<b>x</b> High Confidence Phish needs an admin'); Evidence = @(1..30 | ForEach-Object { [pscustomobject]@{ Received = "row $_"; Sender = 'bob@vendor.com' } }) }
                [pscustomobject]@{ Title = 'Mailbox quota and archive'; Status = 'OK'; Summary = 'Fine.'; Findings = @(); Evidence = [pscustomobject]@{ TotalItemSize = '1 GB'; ArchiveSize = $null } }
            )
        }
    }
    It 'writes classic-safe Markdown (bold, numbered list) with no HTML and states the zone' {
        $T = ConvertTo-CIPPMailTriageNote -Bundle $script:Bundle
        $T | Should -Match '\*\*Mail delivery triage \(CIPP\)\*\* - overall: \*\*Problem\*\*'
        $T | Should -Match '(?m)^1\. \*\*Quarantine \(admin view\): Problem\*\*'
        $T | Should -Match '(?m)^2\. \*\*Mailbox quota and archive: OK\*\*'
        $T | Should -Match 'US Central with UTC'
        $T | Should -Not -Match '<b>'
        $T | Should -Match '\.\.\.and 25 more in CIPP'
        $T | Should -Not -Match 'ArchiveSize'
    }
    It 'stays under the length cap by dropping evidence first' {
        $T = ConvertTo-CIPPMailTriageNote -Bundle $script:Bundle -MaxLength 900
        $T.Length | Should -BeLessOrEqual 900
        $T | Should -Match 'Quarantine \(admin view\): Problem'
    }
}
