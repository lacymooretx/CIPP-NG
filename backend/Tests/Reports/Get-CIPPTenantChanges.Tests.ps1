# Aspendora fork (Vikunja CIPP-58, stage 1): the per-tenant change record. Dates are ISO strings, as the tables hold them.
# The rule under test throughout: a source that could not be read is never reported as no changes.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Core = Join-Path $RepoRoot 'Modules/CIPPCore/Public'
    foreach ($Name in 'ConvertTo-CIPPTenantChangeUtc', 'Get-CIPPTenantChangeAlerts', 'Get-CIPPTenantChangeTests', 'Get-CIPPTenantChangeSecureScore', 'Get-CIPPTenantChangeMessageCenter', 'Get-CIPPTenantChangeHealth', 'Get-CIPPTenantChanges') {
        . (Join-Path $Core "TenantChanges/$Name.ps1")
    }
    . (Join-Path $Core 'IntuneOps/Format-CIPPCentralTime.ps1')
    . (Join-Path $Core 'MessageCenter/Get-CIPPMessageCenterClassification.ps1')
    . (Join-Path $Core 'MessageCenter/Get-CIPPMessageCenterDigest.ps1')
    . (Get-ChildItem -Path $Core -Recurse -Filter 'Get-CippBulkStatusCode.ps1').FullName
    . (Get-ChildItem -Path $Core -Recurse -Filter 'Get-CippErrorStatusCode.ps1').FullName

    class HttpResponseContext {
        [object]$StatusCode
        [object]$Body
    }
    $Accelerators = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    if (-not $Accelerators::Get.ContainsKey('HttpStatusCode')) {
        $Accelerators::Add('HttpStatusCode', [System.Net.HttpStatusCode])
    }
    . (Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Tenant/Reports/Invoke-ListTenantChanges.ps1')

    function Get-Tenants { param($TenantFilter, [switch]$IncludeErrors) }
    function Get-CIPPTable { param($tablename) }
    function Get-CIPPAzDataTableEntity { [CmdletBinding()] param($Context, $Filter, $Property) }
    function ConvertTo-CIPPODataFilterValue { param($Value, $Type) $Value }
    function Get-CIPPDbItem { param($TenantFilter, $Type, [switch]$ByTenant, [switch]$CountsOnly, $Partition) }
    function Get-CIPPPostureChange { param($TenantFilter, $MinDays) }
    function Get-CIPPSecureScoreReport { param($TenantFilter, [switch]$IncludeHistory) }
    function New-GraphGetRequest { param($uri, $tenantid) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) }

    # 2026-11-03 12:00 CST.
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-03T18:00:00', [System.DateTimeKind]::Utc)
    $script:Tenant = 'contoso.onmicrosoft.com'

    function New-AlertRow {
        param($Status = 'Open', $FirstSeen = '2026-10-01T10:00:00.0000000Z', $LastSeen = '2026-11-03T10:00:00.0000000Z', $ResolvedAt = '', $ReopenCount = '0', $SnoozeVisible = '', $Preview = 'an item')
        [pscustomobject]@{
            PartitionKey   = $script:Tenant
            CmdletName     = 'Get-CIPPAlertStorageQuota'
            Status         = $Status
            FirstSeen      = $FirstSeen
            LastSeen       = $LastSeen
            ResolvedAt     = $ResolvedAt
            ReopenCount    = $ReopenCount
            SnoozeVisible  = $SnoozeVisible
            ContentPreview = $Preview
            AlertItem      = '{"Message":"raw field that must not leave"}'
        }
    }

    function New-PostureDiff {
        param($HasPrevious = $true, $PreviousDate = '2026-11-02', $DaysBetween = 1, $Tests = 400, $Errors = @(), $NewIssues = @(), $Fixed = @(), $TestsLastRun = '2026-11-03T08:00:00.0000000Z', $NoLongerAssessed = 0)
        [pscustomobject]@{
            HasPrevious  = $HasPrevious
            PreviousDate = $PreviousDate
            DaysBetween  = $DaysBetween
            TestsLastRun = $TestsLastRun
            Errors       = $Errors
            NewIssues    = $NewIssues
            Fixed        = $Fixed
            Counts       = [pscustomobject]@{ Tests = $Tests; NewIssues = @($NewIssues).Count; Fixed = @($Fixed).Count; NoLongerAssessed = $NoLongerAssessed }
        }
    }

    function New-PostureItem {
        param($Name = 'A test', $Risk = 'High', $Change = 'Was passing')
        [pscustomobject]@{ Name = $Name; Suite = 'ZTNA'; Category = 'Identity'; Risk = $Risk; Change = $Change }
    }

    function New-ScoreReport {
        param($Percent = 62.0, $CapturedAt = '2026-11-03T02:00:00Z', $History)
        [pscustomobject]@{ PercentageScore = $Percent; CapturedAt = $CapturedAt; History = $History }
    }

    function New-ScorePoint {
        param($Date, $Percent)
        [pscustomobject]@{ Date = $Date; PercentageScore = $Percent; CurrentScore = 1 }
    }

    function New-DigestItem {
        param($Id = 'MC1', $Notify = $true, $WindowReason = 'Deadline approaching', $DaysLeft = $null, $Deadline = '')
        [pscustomobject]@{
            MessageId      = $Id
            Title          = 'A post'
            CategoryLabel  = 'Action required / deadline'
            Notify         = $Notify
            WindowReason   = $WindowReason
            DaysLeft       = $DaysLeft
            Deadline       = $Deadline
            PublishedUtc   = '2026-11-03T01:00:00.0000000Z'
            LastUpdatedUtc = '2026-11-03T02:00:00.0000000Z'
            Link           = "https://admin.microsoft.com/#/MessageCenter/:/messages/$Id"
        }
    }

    function New-Digest {
        param($Items = @(), $CacheUtc = '2026-11-03T09:00:00.0000000Z')
        [pscustomobject]@{ Items = $Items; Errors = [string[]]@(); Summary = [pscustomobject]@{ PostsRead = 650; OldestCacheUtc = $CacheUtc } }
    }

    # Every source healthy and nothing changed, for the assembler and endpoint tests to break one at a time.
    function Set-QuietTenant {
        Mock Get-Tenants { [pscustomobject]@{ defaultDomainName = $script:Tenant; customerId = 'guid' } }
        Mock Get-CIPPTable { @{ Context = 'x' } }
        Mock Get-CIPPAzDataTableEntity { New-AlertRow }
        Mock Get-CIPPPostureChange { New-PostureDiff }
        Mock Get-CIPPSecureScoreReport {
            New-ScoreReport -History @((New-ScorePoint '2026-11-02T02:00:00Z' 62.0), (New-ScorePoint '2026-11-03T02:00:00Z' 62.0))
        }
        Mock Get-CIPPMessageCenterDigest { New-Digest }
        Mock Get-CIPPDbItem { [pscustomobject]@{ RowKey = 'Users-Count'; Timestamp = '2026-11-03T09:00:00Z' } }
    }
}

Describe 'ConvertTo-CIPPTenantChangeUtc' {
    It 'reads ISO strings, offsets and every datetime kind as UTC' {
        (ConvertTo-CIPPTenantChangeUtc -Value '2026-11-03T12:00:00-06:00').Hour | Should -Be 18
        (ConvertTo-CIPPTenantChangeUtc -Value '2026-11-03T18:00:00').Hour | Should -Be 18
        (ConvertTo-CIPPTenantChangeUtc -Value ([datetimeoffset]'2026-11-03T12:00:00-06:00')).Hour | Should -Be 18
        (ConvertTo-CIPPTenantChangeUtc -Value ([datetime]'2026-11-03T18:00:00')).Kind | Should -Be 'Utc'
    }

    It 'returns nothing for empty or unreadable values' {
        ConvertTo-CIPPTenantChangeUtc -Value '' | Should -BeNullOrEmpty
        ConvertTo-CIPPTenantChangeUtc -Value $null | Should -BeNullOrEmpty
        ConvertTo-CIPPTenantChangeUtc -Value 'not a date' | Should -BeNullOrEmpty
    }
}

Describe 'Get-CIPPTenantChangeAlerts' {
    BeforeEach { Mock Get-CIPPTable { @{ Context = 'x' } } }

    It 'splits new, reopened and resolved by the lifecycle fields' {
        Mock Get-CIPPAzDataTableEntity {
            New-AlertRow -FirstSeen '2026-11-03T10:00:00.0000000Z' -Preview 'new one'
            New-AlertRow -FirstSeen '2026-11-03T11:00:00.0000000Z' -ReopenCount '2' -Preview 'came back'
            New-AlertRow -Status 'Resolved' -ResolvedAt '2026-11-03T12:00:00.0000000Z' -Preview 'gone'
            New-AlertRow -Preview 'old and continuing'
            New-AlertRow -Status 'Resolved' -ResolvedAt '2026-10-20T12:00:00.0000000Z' -Preview 'long gone'
        }
        $Result = Get-CIPPTenantChangeAlerts -Tenant $script:Tenant -Now $script:Now
        $Result.Status | Should -Be 'OK'
        $Result.New | Should -Be 1
        $Result.Reopened | Should -Be 1
        $Result.Resolved | Should -Be 1
        ($Result.Changes | Where-Object Detail -EQ 'came back').Change | Should -Be 'Reopened'
        $Result.Changes.Detail | Should -Not -Contain 'old and continuing'
        $Result.Changes.Detail | Should -Not -Contain 'long gone'
    }

    It 'names the alert and leaves the raw item behind' {
        Mock Get-CIPPAzDataTableEntity { New-AlertRow -FirstSeen '2026-11-03T10:00:00.0000000Z' }
        $Result = @((Get-CIPPTenantChangeAlerts -Tenant $script:Tenant -Now $script:Now).Changes)
        $Result[0].Title | Should -Be 'Storage Quota'
        $Result[0].When | Should -Be '2026-11-03 04:00 CST (10:00 UTC)'
        $Result[0].PSObject.Properties.Name | Should -Not -Contain 'AlertItem'
    }

    It 'counts a hidden snooze but lists a visible one' {
        Mock Get-CIPPAzDataTableEntity {
            New-AlertRow -Status 'Snoozed' -FirstSeen '2026-11-03T10:00:00.0000000Z' -Preview 'hidden'
            New-AlertRow -Status 'Snoozed' -FirstSeen '2026-11-03T10:00:00.0000000Z' -SnoozeVisible 'True' -Preview 'visible'
        }
        $Result = Get-CIPPTenantChangeAlerts -Tenant $script:Tenant -Now $script:Now
        $Result.Snoozed | Should -Be 1
        @($Result.Changes).Count | Should -Be 1
        @($Result.Changes)[0].Detail | Should -Be 'visible'
    }

    It 'reports the age of an open row that has gone stale without calling it a change' {
        Mock Get-CIPPAzDataTableEntity { New-AlertRow -LastSeen '2026-10-17T03:46:00.0000000Z' }
        $Result = Get-CIPPTenantChangeAlerts -Tenant $script:Tenant -Now $script:Now
        $Result.StaleOpen | Should -Be 1
        @($Result.Changes).Count | Should -Be 0
        $Result.Detail | Should -Match '2026-10-16 22:46 CDT \(03:46 UTC\)'
    }

    It 'does not treat an empty partition as all clear' {
        Mock Get-CIPPAzDataTableEntity { }
        $Result = Get-CIPPTenantChangeAlerts -Tenant $script:Tenant -Now $script:Now
        $Result.Status | Should -Be 'NotComparable'
        $Result.New | Should -BeNullOrEmpty
    }

    It 'cannot call the tenant quiet with a row it could not date' {
        Mock Get-CIPPAzDataTableEntity { New-AlertRow -FirstSeen 'garbage' }
        $Result = Get-CIPPTenantChangeAlerts -Tenant $script:Tenant -Now $script:Now
        $Result.Undated | Should -Be 1
        $Result.Status | Should -Be 'NotComparable'
    }

    It 'turns the table reader''s non-terminating error into a failure' {
        Mock Get-CIPPAzDataTableEntity { Write-Error 'table is down' }
        { Get-CIPPTenantChangeAlerts -Tenant $script:Tenant -Now $script:Now } | Should -Throw '*table is down*'
    }
}

Describe 'Get-CIPPTenantChangeTests' {
    It 'lists new and fixed tests from a baseline inside the window' {
        Mock Get-CIPPPostureChange { New-PostureDiff -NewIssues @(New-PostureItem -Name 'Broke') -Fixed @(New-PostureItem -Name 'Mended') }
        $Result = Get-CIPPTenantChangeTests -Tenant $script:Tenant -Now $script:Now
        $Result.Status | Should -Be 'OK'
        $Result.NewIssues | Should -Be 1
        ($Result.Changes | Where-Object Title -EQ 'Mended').Change | Should -Be 'Fixed'
        ($Result.Changes | Where-Object Title -EQ 'Broke').When | Should -Be 'Since 2026-11-02'
    }

    It 'asks for a baseline as old as the window and stores nothing' {
        Mock Get-CIPPPostureChange { New-PostureDiff -DaysBetween 7 }
        $null = Get-CIPPTenantChangeTests -Tenant $script:Tenant -Days 7 -Now $script:Now
        Should -Invoke Get-CIPPPostureChange -Times 1 -ParameterFilter { $MinDays -eq 7 -and -not $PSBoundParameters.ContainsKey('Snapshot') }
    }

    It 'keeps changes from an old snapshot out of the window' {
        Mock Get-CIPPPostureChange { New-PostureDiff -PreviousDate '2026-10-05' -DaysBetween 29 -NewIssues @(New-PostureItem) }
        $Result = Get-CIPPTenantChangeTests -Tenant $script:Tenant -Now $script:Now
        $Result.Status | Should -Be 'NotComparable'
        @($Result.Changes).Count | Should -Be 0
        @($Result.OlderChanges).Count | Should -Be 1
        $Result.NewIssues | Should -BeNullOrEmpty
        $Result.Detail | Should -Match '2026-10-05'
    }

    It 'says there is no baseline when no snapshot exists' {
        Mock Get-CIPPPostureChange { New-PostureDiff -HasPrevious $false -PreviousDate $null -DaysBetween $null }
        (Get-CIPPTenantChangeTests -Tenant $script:Tenant -Now $script:Now).Status | Should -Be 'NotComparable'
    }

    It 'fails when no results are stored, or the read reported an error' {
        Mock Get-CIPPPostureChange { New-PostureDiff -Tests 0 }
        { Get-CIPPTenantChangeTests -Tenant $script:Tenant -Now $script:Now } | Should -Throw '*No stored test results*'
        Mock Get-CIPPPostureChange { New-PostureDiff -Errors @('Test results could not be read: nope') }
        { Get-CIPPTenantChangeTests -Tenant $script:Tenant -Now $script:Now } | Should -Throw '*nope*'
    }

    It 'leaves a Secure Score error to the Secure Score source' {
        Mock Get-CIPPPostureChange { New-PostureDiff -Errors @('Secure Score could not be read: nope') }
        (Get-CIPPTenantChangeTests -Tenant $script:Tenant -Now $script:Now).Status | Should -Be 'OK'
    }

    It 'marks an old test run as stale' {
        Mock Get-CIPPPostureChange { New-PostureDiff -TestsLastRun '2026-10-20T08:00:00.0000000Z' }
        (Get-CIPPTenantChangeTests -Tenant $script:Tenant -Now $script:Now).Status | Should -Be 'Stale'
    }
}

Describe 'Get-CIPPTenantChangeSecureScore' {
    It 'lists a move at the threshold, against yesterday''s point' {
        Mock Get-CIPPSecureScoreReport {
            New-ScoreReport -Percent 63.0 -History @((New-ScorePoint '2026-10-20T02:00:00Z' 40.0), (New-ScorePoint '2026-11-02T03:30:00Z' 62.0), (New-ScorePoint '2026-11-03T02:00:00Z' 63.0))
        }
        $Result = Get-CIPPTenantChangeSecureScore -Tenant $script:Tenant -Now $script:Now
        $Result.Delta | Should -Be 1
        @($Result.Changes)[0].Change | Should -Be 'Score up'
    }

    It 'stays silent under the threshold but still reports the score' {
        Mock Get-CIPPSecureScoreReport {
            New-ScoreReport -Percent 61.6 -History @((New-ScorePoint '2026-11-02T02:00:00Z' 62.0), (New-ScorePoint '2026-11-03T02:00:00Z' 61.6))
        }
        $Result = Get-CIPPTenantChangeSecureScore -Tenant $script:Tenant -Now $script:Now
        @($Result.Changes).Count | Should -Be 0
        $Result.Delta | Should -Be -0.4
        $Result.Status | Should -Be 'OK'
    }

    It 'says so when there is no earlier point' {
        Mock Get-CIPPSecureScoreReport { New-ScoreReport -History @(New-ScorePoint '2026-11-03T02:00:00Z' 62.0) }
        (Get-CIPPTenantChangeSecureScore -Tenant $script:Tenant -Now $script:Now).Status | Should -Be 'NotComparable'
    }

    It 'fails when nothing is cached' {
        Mock Get-CIPPSecureScoreReport { @() }
        { Get-CIPPTenantChangeSecureScore -Tenant $script:Tenant -Now $script:Now } | Should -Throw '*No Secure Score*'
    }

    It 'marks an old score as stale' {
        Mock Get-CIPPSecureScoreReport {
            New-ScoreReport -CapturedAt '2026-10-20T02:00:00Z' -History @((New-ScorePoint '2026-10-19T02:00:00Z' 62.0), (New-ScorePoint '2026-10-20T02:00:00Z' 62.0))
        }
        (Get-CIPPTenantChangeSecureScore -Tenant $script:Tenant -Now $script:Now).Status | Should -Be 'Stale'
    }
}

Describe 'Get-CIPPTenantChangeMessageCenter' {
    It 'lists alerting posts that are new or updated and skips the others' {
        Mock Get-CIPPMessageCenterDigest {
            New-Digest -Items @(
                (New-DigestItem -Id 'MC1' -WindowReason 'New')
                (New-DigestItem -Id 'MC2' -WindowReason 'Updated')
                (New-DigestItem -Id 'MC3' -WindowReason 'New' -Notify $false)
            )
        }
        $Result = @((Get-CIPPTenantChangeMessageCenter -Tenant $script:Tenant -Now $script:Now).Changes)
        $Result.Count | Should -Be 2
        ($Result | Where-Object Title -Like 'MC1*').Change | Should -Be 'New post'
        ($Result | Where-Object Title -Like 'MC2*').Change | Should -Be 'Updated post'
    }

    It 'shows a deadline on the day it reaches 30, 7 or 0, and not between' {
        Mock Get-CIPPMessageCenterDigest {
            New-Digest -Items @(30, 29, 8, 7, 1, 0 | ForEach-Object { New-DigestItem -Id "MC$_" -DaysLeft $_ -Deadline '2026-12-01' })
        }
        $Result = @((Get-CIPPTenantChangeMessageCenter -Tenant $script:Tenant -Now $script:Now).Changes)
        ($Result.Title | ForEach-Object { ($_ -split ':')[0] }) | Should -Be @('MC30', 'MC7', 'MC0')
        $Result[0].Change | Should -Be 'Deadline in 30 days'
        $Result[2].Change | Should -Be 'Deadline today'
    }

    It 'widens the milestone to the window, so a weekly reader still sees it' {
        Mock Get-CIPPMessageCenterDigest { New-Digest -Items @(New-DigestItem -DaysLeft 25 -Deadline '2026-11-28') }
        @((Get-CIPPTenantChangeMessageCenter -Tenant $script:Tenant -Days 7 -Now $script:Now).Changes).Count | Should -Be 1
    }

    It 'asks the digest for held data only, with a day of slack for the nightly cache' {
        Mock Get-CIPPMessageCenterDigest { New-Digest }
        $null = Get-CIPPTenantChangeMessageCenter -Tenant $script:Tenant -Now $script:Now
        Should -Invoke Get-CIPPMessageCenterDigest -Times 1 -ParameterFilter { $CacheOnly -and $Days -eq 2 }
    }

    It 'marks an old cache as stale' {
        Mock Get-CIPPMessageCenterDigest { New-Digest -CacheUtc '2026-10-01T09:00:00.0000000Z' }
        (Get-CIPPTenantChangeMessageCenter -Tenant $script:Tenant -Now $script:Now).Status | Should -Be 'Stale'
    }

    It 'lets the real digest refuse to go live when nothing is cached' {
        Mock Get-CIPPDbItem { [ordered]@{} }
        Mock New-GraphGetRequest { @() }
        { Get-CIPPTenantChangeMessageCenter -Tenant $script:Tenant -Now $script:Now } | Should -Throw '*No Message Center posts are cached*'
        Should -Invoke New-GraphGetRequest -Times 0
    }

    It 'reads a deadline milestone through the real digest and classifier' {
        Mock Get-CIPPDbItem {
            $Post = [pscustomobject]@{
                id = 'MC42'; title = 'Action required: a retirement'; category = 'planForChange'; severity = 'normal'; tags = @('Admin impact'); services = @('Exchange Online')
                isMajorChange = $false; actionRequiredByDateTime = '2026-11-10T18:00:00Z'; startDateTime = '2026-01-01T00:00:00Z'; lastModifiedDateTime = '2026-01-01T00:00:00Z'
                details = @([pscustomobject]@{ name = 'Summary'; value = '' })
            }
            [ordered]@{ 'contoso.onmicrosoft.com' = @([pscustomobject]@{ Data = ($Post | ConvertTo-Json -Depth 5); Timestamp = '2026-11-03T09:00:00Z' }) }
        }
        $Result = Get-CIPPTenantChangeMessageCenter -Tenant $script:Tenant -Now $script:Now
        $Result.Status | Should -Be 'OK'
        @($Result.Changes)[0].Change | Should -Be 'Deadline in 7 days'
        @($Result.Changes)[0].Link | Should -Match 'MC42'
    }
}

Describe 'Get-CIPPTenantChangeHealth' {
    It 'lists old cache types, oldest first, without being a change' {
        Mock Get-CIPPDbItem {
            [pscustomobject]@{ RowKey = 'Users-Count'; Timestamp = '2026-11-03T09:00:00Z' }
            [pscustomobject]@{ RowKey = 'CredentialUserRegistrationDetails-Count'; Timestamp = '2026-10-05T09:00:00Z' }
            [pscustomobject]@{ RowKey = 'Guests-Count'; Timestamp = [datetimeoffset]'2026-10-20T09:00:00Z' }
        }
        $Result = Get-CIPPTenantChangeHealth -Tenant $script:Tenant -Now $script:Now
        $Result.Status | Should -Be 'OK'
        $Result.OldTypes | Should -Be 2
        $Result.Detail | Should -Match 'CredentialUserRegistrationDetails \(2026-10-05\), Guests \(2026-10-20\)'
        @($Result.Changes).Count | Should -Be 0
    }

    It 'is stale when even the newest type is old, and fails with no rows' {
        Mock Get-CIPPDbItem { [pscustomobject]@{ RowKey = 'Users-Count'; Timestamp = '2026-10-05T09:00:00Z' } }
        (Get-CIPPTenantChangeHealth -Tenant $script:Tenant -Now $script:Now).Status | Should -Be 'Stale'
        Mock Get-CIPPDbItem { }
        { Get-CIPPTenantChangeHealth -Tenant $script:Tenant -Now $script:Now } | Should -Throw '*No cached data*'
    }
}

Describe 'Get-CIPPTenantChanges' {
    BeforeEach { Set-QuietTenant }

    It 'is Quiet only when nothing changed and every source read cleanly' {
        $Record = Get-CIPPTenantChanges -TenantFilter $script:Tenant -Now $script:Now
        $Record.Verdict | Should -Be 'Quiet'
        @($Record.Changes).Count | Should -Be 0
        $Record.Summary.SourcesFailed | Should -Be 0
        $Record.Summary.NewAlerts | Should -Be 0
        @($Record.Sources).Count | Should -Be 5
    }

    It 'resolves a customerId to the tenant''s domain for every source' {
        $null = Get-CIPPTenantChanges -TenantFilter 'guid' -Now $script:Now
        Should -Invoke Get-CIPPPostureChange -Times 1 -ParameterFilter { $TenantFilter -eq 'contoso.onmicrosoft.com' }
        Should -Invoke Get-CIPPAzDataTableEntity -Times 1 -ParameterFilter { $Filter -eq "PartitionKey eq 'contoso.onmicrosoft.com'" }
    }

    It 'reports a failed source as could not read, with null counts rather than zero' {
        Mock Get-CIPPAzDataTableEntity { throw 'table is down' }
        $Record = Get-CIPPTenantChanges -TenantFilter $script:Tenant -Now $script:Now
        $Alerts = $Record.Sources | Where-Object Name -EQ 'Alerts'
        $Alerts.Status | Should -Be 'CouldNotRead'
        $Alerts.StatusText | Should -Be 'Could not read'
        $Alerts.Detail | Should -Match 'table is down'
        $Alerts.ChangeCount | Should -BeNullOrEmpty
        $Record.Summary.NewAlerts | Should -BeNullOrEmpty
        $Record.Summary.ResolvedAlerts | Should -BeNullOrEmpty
        $Record.Verdict | Should -Be 'Incomplete'
    }

    It 'still shows the other sources when one fails' {
        Mock Get-CIPPPostureChange { throw 'no tests' }
        Mock Get-CIPPMessageCenterDigest { New-Digest -Items @(New-DigestItem -WindowReason 'New') }
        $Record = Get-CIPPTenantChanges -TenantFilter $script:Tenant -Now $script:Now
        $Record.Verdict | Should -Be 'Changes'
        @($Record.Changes).Count | Should -Be 1
        ($Record.Sources | Where-Object Name -EQ 'Tests').Status | Should -Be 'CouldNotRead'
    }

    It 'is Incomplete when a source has nothing to compare with' {
        Mock Get-CIPPPostureChange { New-PostureDiff -PreviousDate '2026-10-05' -DaysBetween 29 }
        (Get-CIPPTenantChanges -TenantFilter $script:Tenant -Now $script:Now).Verdict | Should -Be 'Incomplete'
    }

    It 'does not let old test changes break the quiet list, but keeps them available' {
        Mock Get-CIPPPostureChange { New-PostureDiff -PreviousDate '2026-10-05' -DaysBetween 29 -NewIssues @(New-PostureItem) }
        $Record = Get-CIPPTenantChanges -TenantFilter $script:Tenant -Now $script:Now
        @($Record.Changes).Count | Should -Be 0
        @($Record.OlderTestChanges).Count | Should -Be 1
        $Record.TestBaselineDate | Should -Be '2026-10-05'
    }

    It 'does not let an old cache type hold back Quiet' {
        Mock Get-CIPPDbItem { [pscustomobject]@{ RowKey = 'Users-Count'; Timestamp = '2026-10-01T09:00:00Z' } }
        (Get-CIPPTenantChanges -TenantFilter $script:Tenant -Now $script:Now).Verdict | Should -Be 'Quiet'
    }

    It 'is Unreadable when every source fails' {
        Mock Get-CIPPAzDataTableEntity { throw 'a' }
        Mock Get-CIPPPostureChange { throw 'b' }
        Mock Get-CIPPSecureScoreReport { throw 'c' }
        Mock Get-CIPPMessageCenterDigest { throw 'd' }
        Mock Get-CIPPDbItem { throw 'e' }
        $Record = Get-CIPPTenantChanges -TenantFilter $script:Tenant -Now $script:Now
        $Record.Verdict | Should -Be 'Unreadable'
        $Record.Summary.SourcesFailed | Should -Be 5
    }

    It 'throws a typed error for an unknown tenant' {
        Mock Get-Tenants { }
        { Get-CIPPTenantChanges -TenantFilter 'nope' -Now $script:Now } | Should -Throw -ExceptionType ([System.Management.Automation.ItemNotFoundException])
    }
}

Describe 'Invoke-ListTenantChanges' {
    BeforeEach { Set-QuietTenant }

    BeforeAll {
        function New-ChangesRequest {
            param($TenantFilter = 'contoso.onmicrosoft.com', $Days)
            $Query = @{ tenantFilter = $TenantFilter }
            if ($null -ne $Days) { $Query.days = $Days }
            [pscustomobject]@{
                Params  = @{ CIPPEndpoint = 'ListTenantChanges' }
                Headers = @{ }
                Query   = [pscustomobject]$Query
            }
        }
    }

    It 'returns 200 when every source was read' {
        $Response = Invoke-ListTenantChanges -Request (New-ChangesRequest)
        [int]$Response.StatusCode | Should -Be 200
        $Response.Body.Verdict | Should -Not -BeNullOrEmpty
    }

    It 'returns 207 with the record when one source failed' {
        Mock Get-CIPPSecureScoreReport { throw 'nope' }
        $Response = Invoke-ListTenantChanges -Request (New-ChangesRequest)
        [int]$Response.StatusCode | Should -Be 207
        ($Response.Body.Sources | Where-Object Name -EQ 'SecureScore').Status | Should -Be 'CouldNotRead'
    }

    It 'returns 500 with the record when every source failed' {
        Mock Get-CIPPAzDataTableEntity { throw 'a' }
        Mock Get-CIPPPostureChange { throw 'b' }
        Mock Get-CIPPSecureScoreReport { throw 'c' }
        Mock Get-CIPPMessageCenterDigest { throw 'd' }
        Mock Get-CIPPDbItem { throw 'e' }
        $Response = Invoke-ListTenantChanges -Request (New-ChangesRequest)
        [int]$Response.StatusCode | Should -Be 500
        $Response.Body.Verdict | Should -Be 'Unreadable'
    }

    It 'refuses AllTenants and a missing tenant' {
        [int](Invoke-ListTenantChanges -Request (New-ChangesRequest -TenantFilter 'AllTenants')).StatusCode | Should -Be 400
        [int](Invoke-ListTenantChanges -Request (New-ChangesRequest -TenantFilter '')).StatusCode | Should -Be 400
    }

    It 'returns 404 for an unknown tenant' {
        Mock Get-Tenants { }
        [int](Invoke-ListTenantChanges -Request (New-ChangesRequest -TenantFilter 'nope')).StatusCode | Should -Be 404
    }

    It 'defaults and clamps the window' {
        (Invoke-ListTenantChanges -Request (New-ChangesRequest)).Body.Days | Should -Be 1
        (Invoke-ListTenantChanges -Request (New-ChangesRequest -Days 'x')).Body.Days | Should -Be 1
        (Invoke-ListTenantChanges -Request (New-ChangesRequest -Days 7)).Body.Days | Should -Be 7
        (Invoke-ListTenantChanges -Request (New-ChangesRequest -Days 999)).Body.Days | Should -Be 30
    }
}
