# Pester tests for the session timeline (Vikunja CIPP-12): ConvertTo-CIPPSessionTimeline, ConvertTo-CIPPSessionList,
# Start-CIPPSessionTimelineSearch and Get-CIPPSessionTimeline.
# Pins which audit fields tie a record to a session (AppAccessContext.AADSessionId, SessionId, DeviceProperties
# SessionId, AppAccessContext.UniqueTokenId against the session's sign-in tokens), that other sessions and look-alike
# tokens are excluded, US Central conversion, summary counts, that mail subjects never reach the output, and that
# empty results stay arrays. All identifiers, users and IPs are synthetic (RFC 5737 documentation ranges).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Modules = Join-Path $RepoRoot 'Modules'
    foreach ($Name in 'ConvertTo-CIPPSessionTimeline.ps1', 'ConvertTo-CIPPSessionList.ps1', 'Start-CIPPSessionTimelineSearch.ps1',
        'Get-CIPPSessionTimeline.ps1', 'Get-CIPPSessionTimelineSignIns.ps1', 'ConvertTo-CIPPCentralTime.ps1', 'ConvertTo-CIPPBecHostAddress.ps1') {
        $Path = Get-ChildItem -Path $Modules -Recurse -Filter $Name -File | Select-Object -First 1 -ExpandProperty FullName
        if (-not $Path) { throw "Could not locate $Name" }
        . $Path
    }

    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $AsApp, $noPagination, [switch]$ComplexFilter) }
    function New-CippAuditLogSearch { [CmdletBinding()] param($DisplayName, $TenantFilter, $StartTime, $EndTime, $RecordTypeFilters, $UserPrincipalNameFilters) }
    function Get-CippAuditLogSearchResults { [CmdletBinding()] param($TenantFilter, $QueryId) }
    function Get-CippException { [CmdletBinding()] param($Exception) @{ NormalizedError = "$Exception" } }

    $script:Session = '11111111-2222-3333-4444-555555555555'
    $script:Other = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    $script:Token = 'TokA-b64_xyz'

    # Records go through JSON so they have the shape Graph returns (and dates are re-typed as ConvertFrom-Json does).
    function script:New-Record {
        param([string]$Id, [string]$Time, [string]$Service, [string]$Operation, [hashtable]$AuditData = @{}, [string]$ClientIp)
        $R = [ordered]@{ id = $Id; createdDateTime = $Time; service = $Service; operation = $Operation; clientIp = $ClientIp; userPrincipalName = 'user1@contoso.com'; auditData = $AuditData }
        $R | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    }
    function script:New-SignIn {
        param([string]$Id, [string]$Time, [bool]$Interactive = $true, [int]$ErrorCode = 0, [string]$TokenId, [string]$Ip = '203.0.113.10')
        $S = [ordered]@{
            id = $Id; createdDateTime = $Time; userPrincipalName = 'user1@contoso.com'; appDisplayName = 'Office 365 Exchange Online'
            resourceDisplayName = 'Office 365 Exchange Online'; ipAddress = $Ip; userAgent = 'Mozilla/5.0 test'; status = @{ errorCode = $ErrorCode }
            location = @{ city = 'Testville'; countryOrRegion = 'US' }; isInteractive = $Interactive
            signInEventTypes = @(if ($Interactive) { 'interactiveUser' } else { 'nonInteractiveUser' }); uniqueTokenIdentifier = $TokenId; sessionId = $script:Session
        }
        $S | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    }

    function script:Get-Fixture {
        $Aad = @{ AADSessionId = $script:Session; UniqueTokenId = 'unrelated' }
        $Records = @(
            # Exchange mailbox read, matched by AADSessionId; subjects must never be returned
            New-Record -Id 'r1' -Time '2026-07-15T15:00:00Z' -Service 'Exchange' -Operation 'MailItemsAccessed' -ClientIp '203.0.113.10:51234' -AuditData @{
                AppAccessContext = $Aad; ClientInfoString = 'Client=OWA;Mozilla/5.0'; OperationCount = 2
                Folders = @(@{ Path = '\Inbox'; FolderItems = @(@{ InternetMessageId = '<m1@contoso.com>'; Subject = 'SECRET SUBJECT ONE' }, @{ InternetMessageId = '<m2@contoso.com>'; Subject = 'SECRET SUBJECT TWO' }) })
            }
            # Send with no AADSessionId: matched only through the sign-in token
            New-Record -Id 'r2' -Time '2026-07-15T15:05:00Z' -Service 'Exchange' -Operation 'Send' -AuditData @{
                AppAccessContext = @{ UniqueTokenId = $script:Token }; ClientIPAddress = '203.0.113.10'
                Item = @{ InternetMessageId = '<sent1@contoso.com>'; Subject = 'SECRET SENT SUBJECT'; ParentFolder = @{ Path = '\Sent Items' } }
            }
            # Exchange admin cmdlet: top-level SessionId, upper case
            New-Record -Id 'r3' -Time '2026-07-15T15:10:00Z' -Service 'Exchange' -Operation 'New-InboxRule' -AuditData @{
                SessionId = $script:Session.ToUpperInvariant(); ObjectId = 'user1\Move to RSS'; ClientIP = '[2001:db8::1]:443'
            }
            New-Record -Id 'r4' -Time '2026-07-15T15:20:00Z' -Service 'SharePoint' -Operation 'FileDownloaded' -AuditData @{
                AppAccessContext = $Aad; ObjectId = 'https://contoso.sharepoint.com/sites/fin/Shared Documents/q3.xlsx'; UserAgent = 'curl/8.0'; ClientIP = '198.51.100.7'
            }
            New-Record -Id 'r5' -Time '2026-07-15T15:25:00Z' -Service 'OneDrive' -Operation 'AnonymousLinkCreated' -AuditData @{
                AppAccessContext = $Aad; ObjectId = 'https://contoso-my.sharepoint.com/personal/user1/Documents/payroll.pdf'
            }
            # Entra STS logon in the audit log: DeviceProperties SessionId
            New-Record -Id 'r6' -Time '2026-07-15T14:56:00Z' -Service 'AzureActiveDirectory' -Operation 'UserLoggedIn' -AuditData @{
                DeviceProperties = @(@{ Name = 'OS'; Value = 'Windows' }, @{ Name = 'SessionId'; Value = $script:Session })
                ExtendedProperties = @(@{ Name = 'UserAgent'; Value = 'Mozilla/5.0 sts' })
            }
            New-Record -Id 'r7' -Time '2026-07-15T15:30:00Z' -Service 'MicrosoftTeams' -Operation 'MessageSent' -AuditData @{
                AppAccessContext = $Aad; TeamName = 'Finance'; ChannelName = 'General'
            }
            New-Record -Id 'r8' -Time '2026-07-15T15:12:00Z' -Service 'Exchange' -Operation 'Set-Mailbox' -AuditData @{
                SessionId = $script:Session; Parameters = @(@{ Name = 'Identity'; Value = 'user1' }, @{ Name = 'ForwardingSmtpAddress'; Value = 'smtp:x@example.net' })
            }
            # Duplicate of r1: counted once
            New-Record -Id 'r1' -Time '2026-07-15T15:00:00Z' -Service 'Exchange' -Operation 'MailItemsAccessed' -AuditData @{ AppAccessContext = $Aad }
            # --- not this session ---
            New-Record -Id 'x1' -Time '2026-07-15T15:01:00Z' -Service 'Exchange' -Operation 'MailItemsAccessed' -AuditData @{ AppAccessContext = @{ AADSessionId = $script:Other; UniqueTokenId = 'other' } }
            New-Record -Id 'x2' -Time '2026-07-15T15:02:00Z' -Service 'SharePoint' -Operation 'FileAccessed' -AuditData @{ AppAccessContext = @{ UniqueTokenId = 'TokZ-not-in-session' } }
            # same token text in a different case: base64url is case-sensitive, so this is a different token
            New-Record -Id 'x3' -Time '2026-07-15T15:03:00Z' -Service 'Exchange' -Operation 'Send' -AuditData @{ AppAccessContext = @{ UniqueTokenId = $script:Token.ToLowerInvariant() } }
            New-Record -Id 'x4' -Time '2026-07-15T15:04:00Z' -Service 'AzureActiveDirectory' -Operation 'Update user.' -AuditData @{ ObjectId = 'user1@contoso.com' }
            New-Record -Id 'x5' -Time '2026-07-15T15:06:00Z' -Service 'AzureActiveDirectory' -Operation 'UserLoggedIn' -AuditData @{ DeviceProperties = @(@{ Name = 'SessionId'; Value = $script:Other }) }
        )
        $SignIns = @(
            New-SignIn -Id 's1' -Time '2026-07-15T14:55:00Z' -TokenId $script:Token
            New-SignIn -Id 's2' -Time '2026-07-15T16:40:00Z' -Interactive $false -ErrorCode 50140 -TokenId 'TokB'
        )
        @{ Records = $Records; SignIns = $SignIns }
    }
}

Describe 'ConvertTo-CIPPSessionTimeline' {
    BeforeAll {
        $F = Get-Fixture
        $script:R = ConvertTo-CIPPSessionTimeline -Records $F.Records -SignIns $F.SignIns -SessionId $script:Session
        $script:Audit = @($script:R.Timeline | Where-Object Source -EQ 'AuditLog')
    }

    It 'keeps exactly the records that carry this session' {
        @($script:Audit.RecordId | Sort-Object) | Should -Be @('r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8')
        $script:R.RecordsMatched | Should -Be 8
        $script:R.RecordsRead | Should -Be 14
        $script:R.SignInCount | Should -Be 2
    }

    It 'reports which field matched, per workload' -ForEach @(
        @{ Id = 'r1'; Field = 'AADSessionId' }       # Exchange mailbox item
        @{ Id = 'r2'; Field = 'UniqueTokenId' }      # Exchange Send without AADSessionId
        @{ Id = 'r3'; Field = 'SessionId' }          # Exchange admin cmdlet
        @{ Id = 'r4'; Field = 'AADSessionId' }       # SharePoint
        @{ Id = 'r5'; Field = 'AADSessionId' }       # OneDrive
        @{ Id = 'r6'; Field = 'DeviceSessionId' }    # Entra STS logon
        @{ Id = 'r7'; Field = 'AADSessionId' }       # Teams
    ) {
        ($script:Audit | Where-Object RecordId -EQ $Id).MatchedOn | Should -Be $Field
    }

    It 'counts matches by field' {
        $script:R.MatchedBy.AADSessionId | Should -Be 4
        $script:R.MatchedBy.SessionId | Should -Be 2
        $script:R.MatchedBy.DeviceSessionId | Should -Be 1
        $script:R.MatchedBy.UniqueTokenId | Should -Be 1
    }

    It 'excludes other sessions, unknown and case-changed tokens and records without a session field' {
        @($script:R.Timeline | Where-Object { $_.RecordId -like 'x*' }).Count | Should -Be 0
    }

    It 'sorts the timeline by time and converts to US Central with UTC alongside' {
        $Utc = @($script:R.Timeline.TimeUtc)
        $Utc | Should -Be @($Utc | Sort-Object)
        $script:R.Timeline[0].RecordId | Should -Be 's1'
        ($script:Audit | Where-Object RecordId -EQ 'r1').Time | Should -Be '2026-07-15 10:00 CDT (15:00 UTC)'
        ($script:Audit | Where-Object RecordId -EQ 'r1').TimeUtc | Should -Be '2026-07-15T15:00:00Z'
        $script:R.FirstSeen | Should -Be '2026-07-15 09:55 CDT (14:55 UTC)'
        $script:R.LastSeen | Should -Be '2026-07-15 11:40 CDT (16:40 UTC)'
    }

    It 'uses CST in winter' {
        $Rec = New-Record -Id 'w1' -Time '2026-01-15T15:00:00Z' -Service 'Exchange' -Operation 'Send' -AuditData @{ SessionId = $script:Session }
        $W = ConvertTo-CIPPSessionTimeline -Records @($Rec) -SignIns @() -SessionId $script:Session
        $W.Timeline[0].Time | Should -Be '2026-01-15 09:00 CST (15:00 UTC)'
    }

    It 'never returns mail subjects' {
        ($script:R | ConvertTo-Json -Depth 10) | Should -Not -Match 'SECRET'
        ($script:Audit | Where-Object RecordId -EQ 'r1').Object | Should -Be '2 item(s) in \Inbox'
        ($script:Audit | Where-Object RecordId -EQ 'r2').Object | Should -Be 'Message <sent1@contoso.com> in \Sent Items'
    }

    It 'keeps file paths and Teams names as the object' {
        ($script:Audit | Where-Object RecordId -EQ 'r4').Object | Should -Be 'https://contoso.sharepoint.com/sites/fin/Shared Documents/q3.xlsx'
        ($script:Audit | Where-Object RecordId -EQ 'r7').Object | Should -Be 'Finance / General'
    }

    It 'normalises client addresses and picks the user agent' {
        ($script:Audit | Where-Object RecordId -EQ 'r1').ClientIP | Should -Be '203.0.113.10'
        ($script:Audit | Where-Object RecordId -EQ 'r3').ClientIP | Should -Be '2001:db8::1'
        ($script:Audit | Where-Object RecordId -EQ 'r1').UserAgent | Should -Be 'Client=OWA;Mozilla/5.0'
        ($script:Audit | Where-Object RecordId -EQ 'r4').UserAgent | Should -Be 'curl/8.0'
        ($script:Audit | Where-Object RecordId -EQ 'r6').UserAgent | Should -Be 'Mozilla/5.0 sts'
    }

    It 'summarises what the session did' {
        $H = $script:R.Highlights
        $H.SignIns | Should -Be 2
        $H.FailedSignIns | Should -Be 1
        $H.MailItemsRead | Should -Be 2
        $H.MailsSent | Should -Be 1
        $H.InboxRulesChanged | Should -Be 1
        $H.ForwardingChanged | Should -Be 1
        $H.FilesDownloaded | Should -Be 1
        $H.SharesCreated | Should -Be 1
        $H.TeamsMessagesSent | Should -Be 1
        $H.FilesAccessed | Should -Be 0
    }

    It 'counts per workload, operation and IP' {
        ($script:R.ByWorkload | Where-Object Workload -EQ 'Exchange').Count | Should -Be 4
        ($script:R.ByWorkload | Where-Object Workload -EQ 'Entra sign-in').Count | Should -Be 2
        $Mia = $script:R.ByOperation | Where-Object { $_.Workload -eq 'Exchange' -and $_.Operation -eq 'MailItemsAccessed' }
        $Mia.Records | Should -Be 1
        $Mia.Items | Should -Be 2
        ($script:R.ByIP | Where-Object ClientIP -EQ '203.0.113.10').Count | Should -Be 4
    }

    It 'marks failed sign-ins and interactive versus non-interactive' {
        $S2 = $script:R.Timeline | Where-Object RecordId -EQ 's2'
        $S2.Result | Should -Be 'Failure 50140'
        $S2.Operation | Should -Be 'Sign-in (non-interactive)'
        ($script:R.Timeline | Where-Object RecordId -EQ 's1').Operation | Should -Be 'Sign-in (interactive)'
    }

    It 'returns arrays, not $null, when nothing matches' {
        $E = ConvertTo-CIPPSessionTimeline -Records @() -SignIns @() -SessionId $script:Session
        , $E.Timeline | Should -BeOfType [object[]]
        $E.Timeline.Count | Should -Be 0
        $E.RecordsMatched | Should -Be 0
        $E.FirstSeen | Should -BeNullOrEmpty
        $N = ConvertTo-CIPPSessionTimeline -Records $null -SignIns $null -SessionId $script:Session
        $N.Timeline.Count | Should -Be 0
    }
}

Describe 'ConvertTo-CIPPSessionList' {
    It 'groups sign-ins by session, newest first, and skips sign-ins without a session' {
        $A = New-SignIn -Id 'a1' -Time '2026-07-15T14:00:00Z' -Ip '203.0.113.10'
        $B = New-SignIn -Id 'a2' -Time '2026-07-15T18:00:00Z' -Ip '198.51.100.7' -ErrorCode 50126
        $C = New-SignIn -Id 'b1' -Time '2026-07-16T09:00:00Z'
        $C.sessionId = $script:Other
        $D = New-SignIn -Id 'n1' -Time '2026-07-16T10:00:00Z'
        $D.sessionId = ''
        $L = ConvertTo-CIPPSessionList -SignIns @($A, $B, $C, $D)
        $L.Count | Should -Be 2
        $L[0].SessionId | Should -Be $script:Other
        $L[1].SessionId | Should -Be $script:Session
        $L[1].SignIns | Should -Be 2
        $L[1].Failures | Should -Be 1
        $L[1].FirstSignIn | Should -Be '2026-07-15 09:00 CDT (14:00 UTC)'
        $L[1].IPAddresses | Should -Be '203.0.113.10, 198.51.100.7'
    }

    It 'returns an empty array for no sign-ins and an array for one session' {
        $Empty = ConvertTo-CIPPSessionList -SignIns @()
        , $Empty | Should -BeOfType [object[]]
        $Empty.Count | Should -Be 0
        $One = ConvertTo-CIPPSessionList -SignIns @(New-SignIn -Id 'a1' -Time '2026-07-15T14:00:00Z')
        , $One | Should -BeOfType [object[]]
        $One.Count | Should -Be 1
    }
}

Describe 'Start-CIPPSessionTimelineSearch' {
    BeforeEach {
        $script:SignInPage = @(
            New-SignIn -Id 's1' -Time (Get-Date).ToUniversalTime().AddHours(-5).ToString('o') -TokenId 'T1'
            New-SignIn -Id 's2' -Time (Get-Date).ToUniversalTime().AddHours(-1).ToString('o') -TokenId 'T2'
        )
        Mock New-GraphGetRequest { $script:LastSignInUri = $uri; $script:SignInPage }
        Mock New-CippAuditLogSearch { $script:SearchArgs = @{ UserPrincipalNameFilters = $UserPrincipalNameFilters; RecordTypeFilters = $RecordTypeFilters; StartTime = $StartTime; EndTime = $EndTime }; [pscustomobject]@{ id = '99999999-0000-0000-0000-000000000001'; status = 'notStarted' } }
    }

    It 'filters sign-ins on the session id and both sign-in event types' {
        $null = Start-CIPPSessionTimelineSearch -TenantFilter 'contoso.com' -SessionId $script:Session
        [uri]::UnescapeDataString($script:LastSignInUri) | Should -Match "sessionId eq '$($script:Session)'"
        [uri]::UnescapeDataString($script:LastSignInUri) | Should -Match 'nonInteractiveUser'
    }

    It 'scopes the search to the session user and a window around the sign-ins, capped at now' {
        $R = Start-CIPPSessionTimelineSearch -TenantFilter 'contoso.com' -SessionId $script:Session
        $R.QueryId | Should -Be '99999999-0000-0000-0000-000000000001'
        $R.UserPrincipalName | Should -Be 'user1@contoso.com'
        @($script:SearchArgs.UserPrincipalNameFilters) | Should -Be @('user1@contoso.com')
        @($script:SearchArgs.RecordTypeFilters) | Should -Contain 'exchangeItemAggregated'
        @($script:SearchArgs.RecordTypeFilters) | Should -Contain 'sharePointFileOperation'
        @($script:SearchArgs.RecordTypeFilters) | Should -Contain 'microsoftTeams'
        $Now = (Get-Date).ToUniversalTime()
        $Start = ([datetime]$script:SearchArgs.StartTime).ToUniversalTime()
        $End = ([datetime]$script:SearchArgs.EndTime).ToUniversalTime()
        ($Now - $Start).TotalMinutes | Should -BeGreaterThan 314
        ($Now - $Start).TotalMinutes | Should -BeLessThan 316
        # last sign-in + 2h would be in the future: capped at now
        ($Now - $End).TotalMinutes | Should -BeLessThan 2
    }

    It 'honours an explicit user and window' {
        $S = [datetime]::SpecifyKind([datetime]'2026-07-01T00:00:00', 'Utc')
        $E = [datetime]::SpecifyKind([datetime]'2026-07-02T00:00:00', 'Utc')
        $null = Start-CIPPSessionTimelineSearch -TenantFilter 'contoso.com' -SessionId $script:Session -UserPrincipalName 'other@contoso.com' -StartTime $S -EndTime $E
        @($script:SearchArgs.UserPrincipalNameFilters) | Should -Be @('other@contoso.com')
        ([datetime]$script:SearchArgs.StartTime).ToUniversalTime() | Should -Be $S
        ([datetime]$script:SearchArgs.EndTime).ToUniversalTime() | Should -Be $E
    }

    It 'still starts the search when sign-ins cannot be read but a user and window were given (no Entra ID P1)' {
        Mock New-GraphGetRequest { throw 'Tenant does not have a SKU required' }
        $S = [datetime]::SpecifyKind([datetime]'2026-07-01T00:00:00', 'Utc')
        $E = [datetime]::SpecifyKind([datetime]'2026-07-02T00:00:00', 'Utc')
        $R = Start-CIPPSessionTimelineSearch -TenantFilter 'contoso.com' -SessionId $script:Session -UserPrincipalName 'user1@contoso.com' -StartTime $S -EndTime $E
        $R.QueryId | Should -Not -BeNullOrEmpty
        @($R.Errors).Count | Should -Be 1
        Should -Invoke New-CippAuditLogSearch -Times 1
    }

    It 'refuses when the session has no sign-ins and no user was given' {
        $script:SignInPage = @()
        { Start-CIPPSessionTimelineSearch -TenantFilter 'contoso.com' -SessionId $script:Session } | Should -Throw '*user is unknown*'
        Should -Invoke New-CippAuditLogSearch -Times 0
    }

    It 'rejects a session id that is not a GUID before calling Graph' {
        { Start-CIPPSessionTimelineSearch -TenantFilter 'contoso.com' -SessionId "x' or 1 eq 1" } | Should -Throw '*not a GUID*'
        Should -Invoke New-GraphGetRequest -Times 0
    }
}

Describe 'Get-CIPPSessionTimeline' {
    BeforeEach {
        $F = Get-Fixture
        $script:Fx = $F
        $script:QueryStatus = 'running'
        Mock New-GraphGetRequest {
            if ($uri -like '*security/auditLog/queries/*') {
                return [pscustomobject]@{ status = $script:QueryStatus; approximateReturnedRecordCount = 14; userPrincipalNameFilters = @('user1@contoso.com'); filterStartDateTime = '2026-07-15T14:40:00Z'; filterEndDateTime = '2026-07-15T18:40:00Z'; isRecordCountLimitExceeded = $false }
            }
            if ($uri -like '*auditLogs/signIns*') { return $script:Fx.SignIns }
            throw "unexpected GET $uri"
        }
        Mock Get-CippAuditLogSearchResults { $script:Fx.Records }
    }

    It 'returns only the status while Microsoft is still searching' {
        $R = Get-CIPPSessionTimeline -TenantFilter 'contoso.com' -QueryId '99999999-0000-0000-0000-000000000001' -SessionId $script:Session
        $R.Ready | Should -BeFalse
        $R.Status | Should -Be 'running'
        $R.WindowStart.Display | Should -Be '2026-07-15 09:40 CDT (14:40 UTC)'
        Should -Invoke Get-CippAuditLogSearchResults -Times 0
    }

    It 'builds the timeline once the search has succeeded' {
        $script:QueryStatus = 'succeeded'
        $R = Get-CIPPSessionTimeline -TenantFilter 'contoso.com' -QueryId '99999999-0000-0000-0000-000000000001' -SessionId $script:Session
        $R.Ready | Should -BeTrue
        $R.RecordsMatched | Should -Be 8
        $R.SignInCount | Should -Be 2
        $R.Highlights.MailsSent | Should -Be 1
        $R.Message | Should -Match '8 of 14'
    }

    It 'still matches on session ids when the sign-ins cannot be read' {
        $script:QueryStatus = 'succeeded'
        Mock New-GraphGetRequest {
            if ($uri -like '*security/auditLog/queries/*') { return [pscustomobject]@{ status = 'succeeded' } }
            throw 'Forbidden'
        }
        $R = Get-CIPPSessionTimeline -TenantFilter 'contoso.com' -QueryId '99999999-0000-0000-0000-000000000001' -SessionId $script:Session
        $R.Ready | Should -BeTrue
        $R.RecordsMatched | Should -Be 7   # r2 needed the sign-in token
        @($R.Errors).Count | Should -Be 1
    }

    It 'rejects ids that are not GUIDs' {
        { Get-CIPPSessionTimeline -TenantFilter 'contoso.com' -QueryId 'abc' -SessionId $script:Session } | Should -Throw '*not a GUID*'
    }
}
