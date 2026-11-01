# Aspendora fork (Vikunja CIPP-40): out-of-office exposure detection rules, severity, and the two-pass EXO bulk read.
# All fixtures are synthetic (contoso.com / fabrikam.com); no real auto-reply text is used.

BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Core = Join-Path $BackendRoot 'Modules/CIPPCore/Public'
    foreach ($Name in 'Get-CIPPOooMessageFlags', 'Get-CIPPOooExposureSeverity', 'Get-CIPPOooExposure') {
        . (Join-Path $Core "OooExposure/$Name.ps1")
    }
    . (Join-Path $Core 'IntuneOps/Format-CIPPCentralTime.ps1')
    . (Join-Path $Core 'Alerts/Get-CIPPAlertFailureSeverity.ps1')

    function Test-CIPPStandardLicense { [CmdletBinding()] param($StandardName, $TenantFilter, $Preset, [switch]$SkipLog) }
    function New-ExoRequest { [CmdletBinding()] param($tenantid, $cmdlet, $cmdParams, $Select, $Anchor) }
    function New-ExoBulkRequest { [CmdletBinding()] param($tenantid, $cmdletArray, $Select, $MaxConcurrency) }
    function Get-CippException { [CmdletBinding()] param($Exception) @{ NormalizedError = "$Exception" } }
}

Describe 'Get-CIPPOooMessageFlags' {
    It 'strips HTML and flags a colleague in a mailto link, a phone number, travel, a return date, a title and a finance cue' {
        $Html = '<html><body><p>I am travelling to a conference until Nov 12.</p><p>For urgent invoices contact <a href="mailto:jane.doe@contoso.com">Jane Doe</a>, our Controller, at (555) 123-4567.</p></body></html>'
        $R = Get-CIPPOooMessageFlags -Message $Html -AcceptedDomains @('contoso.com') -OwnAddresses @('amy@contoso.com')
        $R.Flags | Should -Contain 'InternalEmail'
        $R.Flags | Should -Contain 'Phone'
        $R.Flags | Should -Contain 'Travel'
        $R.Flags | Should -Contain 'ReturnDate'
        $R.Flags | Should -Contain 'Title'
        $R.Flags | Should -Contain 'Finance'
        $R.Flags | Should -Not -Contain 'ExternalEmail'
        $R.InternalEmails | Should -Be @('jane.doe@contoso.com')
        $R.PhoneCount | Should -Be 1
        $R.Text | Should -Not -Match '<'
        $R.Text | Should -Match 'Jane Doe'
    }

    It 'masks addresses and phone numbers in the snippet and caps it at 160 characters' {
        $Text = 'Contact bob@contoso.com or call 555.123.4567. ' + ('x' * 300)
        $R = Get-CIPPOooMessageFlags -Message $Text -AcceptedDomains @('contoso.com')
        $R.Snippet | Should -Match '\[email\]'
        $R.Snippet | Should -Match '\[phone\]'
        $R.Snippet | Should -Not -Match 'bob@'
        $R.Snippet | Should -Not -Match '4567'
        $R.Snippet.Length | Should -BeLessOrEqual 160
        $R.Snippet | Should -Match '\.\.\.$'
    }

    It 'ignores the mailbox''s own address and treats accepted-domain subdomains as internal' {
        $R = Get-CIPPOooMessageFlags -Message 'Reply to AMY@contoso.com, or ask ops@mail.contoso.com or partner@fabrikam.com.' -AcceptedDomains @('contoso.com') -OwnAddresses @('amy@contoso.com')
        $R.InternalEmails | Should -Be @('ops@mail.contoso.com')
        $R.ExternalEmails | Should -Be @('partner@fabrikam.com')
        $R.Flags | Should -Contain 'ExternalEmail'
    }

    It 'classifies every address as external when accepted domains are unknown' {
        $R = Get-CIPPOooMessageFlags -Message 'Ask bob@contoso.com.'
        $R.Flags | Should -Be @('ExternalEmail')
    }

    It 'flags a plain out-of-office with nothing' {
        $R = Get-CIPPOooMessageFlags -Message 'Thank you for your email. I am out of the office and will reply when I can.'
        @($R.Flags).Count | Should -Be 0
        $R.Snippet | Should -Be 'Thank you for your email. I am out of the office and will reply when I can.'
    }

    It 'handles an empty or null message' {
        @((Get-CIPPOooMessageFlags -Message $null).Flags).Count | Should -Be 0
        (Get-CIPPOooMessageFlags -Message '').Snippet | Should -Be ''
    }

    It 'finds international numbers and does not read dates or ticket numbers as phones' {
        (Get-CIPPOooMessageFlags -Message 'UK office: +44 20 7946 0958').PhoneCount | Should -Be 1
        $R = Get-CIPPOooMessageFlags -Message 'Back on 2026-11-05 or 11/05/2026. Ticket 12345.'
        $R.PhoneCount | Should -Be 0
        $R.Flags | Should -Contain 'ReturnDate'
    }

    It 'reads a tel: link and "back on Monday"' {
        $R = Get-CIPPOooMessageFlags -Message '<a href="tel:+15551234567">Call the office</a>. I will be back on Monday.'
        $R.PhoneCount | Should -Be 1
        $R.Flags | Should -Contain 'ReturnDate'
    }

    It 'matches ACH only in capitals and A/P with the slash' {
        (Get-CIPPOooMessageFlags -Message 'Each request will wait.').Flags | Should -Not -Contain 'Finance'
        (Get-CIPPOooMessageFlags -Message 'ACH changes go to the office.').Flags | Should -Contain 'Finance'
        (Get-CIPPOooMessageFlags -Message 'Send A/P questions to the team.').Flags | Should -Contain 'Finance'
    }

    It 'drops style blocks and decodes entities' {
        $R = Get-CIPPOooMessageFlags -Message '<style>p{color:red}</style><p>Out&nbsp;today &amp; tomorrow</p>'
        $R.Text | Should -Be 'Out today & tomorrow'
    }
}

Describe 'Get-CIPPOooExposureSeverity' {
    It 'rates <Audience> with <Flags> as <Expected>' -ForEach @(
        @{ Audience = 'All'; Flags = @('InternalEmail'); Expected = 'High' }
        @{ Audience = 'All'; Flags = @('Phone', 'Travel'); Expected = 'High' }
        @{ Audience = 'All'; Flags = @('Finance'); Expected = 'High' }
        @{ Audience = 'All'; Flags = @('Travel', 'ReturnDate', 'Title', 'ExternalEmail'); Expected = 'Medium' }
        @{ Audience = 'All'; Flags = @(); Expected = 'Medium' }
        @{ Audience = 'Known'; Flags = @('InternalEmail', 'Finance'); Expected = 'Low' }
        @{ Audience = 'None'; Flags = @('Phone'); Expected = 'None' }
    ) {
        Get-CIPPOooExposureSeverity -ExternalAudience $Audience -Flags $Flags | Should -Be $Expected
    }
}

Describe 'Get-CIPPOooExposure' {
    BeforeAll {
        $script:Now = [datetime]::new(2026, 11, 4, 15, 0, 0, [System.DateTimeKind]::Utc)
        $script:Mailboxes = @(
            foreach ($Name in 'amy', 'bob', 'carol', 'dan', 'erin', 'fred', 'gina', 'hank') {
                [pscustomobject]@{ UserPrincipalName = "$Name@contoso.com"; PrimarySmtpAddress = "$Name@contoso.com"; DisplayName = "User $Name"; RecipientTypeDetails = 'UserMailbox'; EmailAddresses = @("SMTP:$Name@contoso.com", "smtp:$Name@contoso.onmicrosoft.com") }
            }
        )
        # EXO answers StartTime/EndTime as ISO strings with an offset; stale times stay on Enabled/Disabled replies.
        $script:Config = @{
            'amy@contoso.com'   = @{ AutoReplyState = 'Scheduled'; ExternalAudience = 'All'; StartTime = '2026-11-03T14:00:00+00:00'; EndTime = '2026-11-10T14:00:00+00:00'; ExternalMessage = '<p>Away. For payments ask bob@contoso.com or call 555-123-4567.</p>' }
            'bob@contoso.com'   = @{ AutoReplyState = 'Enabled'; ExternalAudience = 'All'; StartTime = '2025-01-01T00:00:00+00:00'; EndTime = '2025-01-02T00:00:00+00:00'; ExternalMessage = 'Out of office, back on Monday.' }
            'carol@contoso.com' = @{ AutoReplyState = 'Scheduled'; ExternalAudience = 'All'; StartTime = '2026-10-01T00:00:00+00:00'; EndTime = '2026-10-05T00:00:00+00:00'; ExternalMessage = 'old' }
            'dan@contoso.com'   = @{ AutoReplyState = 'Enabled'; ExternalAudience = 'Known'; StartTime = $null; EndTime = $null; ExternalMessage = 'Invoices to ap@contoso.com' }
            'erin@contoso.com'  = @{ AutoReplyState = 'Disabled'; ExternalAudience = 'All'; StartTime = $null; EndTime = $null; ExternalMessage = 'never read' }
            'fred@contoso.com'  = @{ AutoReplyState = 'Enabled'; ExternalAudience = 'None'; StartTime = $null; EndTime = $null; ExternalMessage = 'never read' }
            'gina@contoso.com'  = @{ AutoReplyState = 'Scheduled'; ExternalAudience = 'All'; StartTime = '2026-11-07T14:00:00+00:00'; EndTime = '2026-11-09T14:00:00+00:00'; ExternalMessage = 'Upcoming trip' }
            'hank@contoso.com'  = @{ Error = 'The operation couldn''t be performed because object couldn''t be found' }
        }
    }

    BeforeEach {
        $script:MessageReads = [System.Collections.Generic.List[string]]::new()
        $script:BulkSelects = [System.Collections.Generic.List[string]]::new()
        Mock Test-CIPPStandardLicense { $true }
        Mock New-ExoRequest {
            switch ($cmdlet) {
                'Get-Mailbox' { $script:Mailboxes }
                'Get-AcceptedDomain' { @([pscustomobject]@{ DomainName = 'contoso.com' }) }
            }
        }
        Mock New-ExoBulkRequest {
            $script:BulkSelects.Add([string]$Select)
            foreach ($Cmd in @($cmdletArray)) {
                $Key = [string]$Cmd.OperationGuid
                $C = $script:Config[$Key]
                if ($C.Error) { [pscustomobject]@{ error = $C.Error; target = $Key; OperationGuid = $Key }; continue }
                if ($Select -eq 'ExternalMessage') {
                    $script:MessageReads.Add($Key)
                    [pscustomobject]@{ ExternalMessage = $C.ExternalMessage; OperationGuid = $Key }
                } else {
                    [pscustomobject]@{ AutoReplyState = $C.AutoReplyState; ExternalAudience = $C.ExternalAudience; StartTime = $C.StartTime; EndTime = $C.EndTime; OperationGuid = $Key }
                }
            }
        }
    }

    It 'lists only replies live for external senders, highest severity first' {
        $R = Get-CIPPOooExposure -TenantFilter 'contoso.com' -Now $script:Now
        $R.Status | Should -Be 'OK'
        $R.MailboxesChecked | Should -Be 8
        $R.SettingsRead | Should -Be 7
        $R.Rows.Mailbox | Should -Be @('amy@contoso.com', 'bob@contoso.com', 'dan@contoso.com')
        $R.Rows.Severity | Should -Be @('High', 'Medium', 'Low')
        $R.Summary.High | Should -Be 1
        $R.Summary.Total | Should -Be 3
    }

    It 'reads message bodies only for the live mailboxes, and the first pass never selects them' {
        Get-CIPPOooExposure -TenantFilter 'contoso.com' -Now $script:Now | Out-Null
        @($script:MessageReads | Sort-Object) | Should -Be @('amy@contoso.com', 'bob@contoso.com', 'dan@contoso.com')
        $script:BulkSelects[0] | Should -Not -Match 'Message'
        Should -Invoke New-ExoBulkRequest -Times 2 -Exactly
    }

    It 'flags the colleague and phone number on the High row and keeps the schedule in UTC, Unix and Central' {
        $Amy = (Get-CIPPOooExposure -TenantFilter 'contoso.com' -Now $script:Now).Rows | Where-Object Mailbox -EQ 'amy@contoso.com'
        $Amy.InternalContacts | Should -Be 'bob@contoso.com'
        $Amy.PhoneCount | Should -Be 1
        $Amy.Flags | Should -Contain 'Finance'
        $Amy.StartTime | Should -Be '2026-11-03T14:00:00Z'
        $Amy.EndTimeUnix | Should -Be ([datetimeoffset]::new(2026, 11, 10, 14, 0, 0, [timespan]::Zero).ToUnixTimeSeconds())
        $Amy.StartCentral | Should -Match '^2026-11-03 08:00 CST|UTC$'
        $Amy.Snippet | Should -Not -Match 'bob@|4567'
        $Amy.Window | Should -Be 'Active'
    }

    It 'does not report stale schedule times on an Enabled reply' {
        $Bob = (Get-CIPPOooExposure -TenantFilter 'contoso.com' -Now $script:Now).Rows | Where-Object Mailbox -EQ 'bob@contoso.com'
        $Bob.StartTime | Should -BeNullOrEmpty
        $Bob.StartTimeUnix | Should -BeNullOrEmpty
        $Bob.EndCentral | Should -Be 'No end (Enabled)'
    }

    It 'adds upcoming schedules only when asked' {
        $R = Get-CIPPOooExposure -TenantFilter 'contoso.com' -Now $script:Now -IncludeUpcoming
        ($R.Rows | Where-Object Mailbox -EQ 'gina@contoso.com').Window | Should -Be 'Upcoming'
        (Get-CIPPOooExposure -TenantFilter 'contoso.com' -Now $script:Now -IncludeUpcoming -UpcomingDays 1).Rows.Mailbox | Should -Not -Contain 'gina@contoso.com'
    }

    It 'reports mailboxes whose settings could not be read' {
        $R = Get-CIPPOooExposure -TenantFilter 'contoso.com' -Now $script:Now
        @($R.Errors) -join ' ' | Should -Match '1 of 8 mailboxes'
    }

    It 'returns NoExchange without calling Exchange when the tenant has no Exchange licence' {
        Mock Test-CIPPStandardLicense { $false }
        $R = Get-CIPPOooExposure -TenantFilter 'contoso.com' -Now $script:Now
        $R.Status | Should -Be 'NoExchange'
        Should -Invoke New-ExoRequest -Times 0 -Exactly
    }

    It 'returns NoExchange when Get-Mailbox answers with a licensing error' {
        Mock New-ExoRequest { throw 'The tenant does not have a valid license for Exchange Online' } -ParameterFilter { $cmdlet -eq 'Get-Mailbox' }
        (Get-CIPPOooExposure -TenantFilter 'contoso.com' -Now $script:Now).Status | Should -Be 'NoExchange'
    }

    It 'throws on any other Get-Mailbox failure' {
        Mock New-ExoRequest { throw 'Unauthorized' } -ParameterFilter { $cmdlet -eq 'Get-Mailbox' }
        { Get-CIPPOooExposure -TenantFilter 'contoso.com' -Now $script:Now } | Should -Throw '*Could not list mailboxes*'
    }

    It 'still lists the row (Medium, unreadable) when a message read fails' {
        Mock New-ExoBulkRequest {
            foreach ($Cmd in @($cmdletArray)) {
                $Key = [string]$Cmd.OperationGuid
                if ($Select -eq 'ExternalMessage') { [pscustomobject]@{ error = 'Transient'; OperationGuid = $Key }; continue }
                if ($Key -ne 'amy@contoso.com') { continue }
                $C = $script:Config[$Key]
                [pscustomobject]@{ AutoReplyState = $C.AutoReplyState; ExternalAudience = $C.ExternalAudience; StartTime = $C.StartTime; EndTime = $C.EndTime; OperationGuid = $Key }
            }
        }
        $Row = @((Get-CIPPOooExposure -TenantFilter 'contoso.com' -Now $script:Now).Rows)[0]
        $Row.Severity | Should -Be 'Medium'
        $Row.MessageRead | Should -BeFalse
        $Row.Reasons | Should -Match 'could not be read: Transient'
    }
}
