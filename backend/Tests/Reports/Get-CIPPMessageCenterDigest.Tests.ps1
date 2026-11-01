# Aspendora fork (Vikunja CIPP-37): Message Center classifier, cross-tenant dedupe and the ListMessageCenterDigest
# endpoint. Post shapes mirror live Graph v1.0 admin/serviceAnnouncement/messages posts read on 2026-11-01
# (MC1446796 EWS, MC1325414 SSPR, MC1526468 Canada time zone, MC1526651 Teams QR code).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Core = Join-Path $RepoRoot 'Modules/CIPPCore/Public'
    . (Join-Path $Core 'MessageCenter/Get-CIPPMessageCenterClassification.ps1')
    . (Join-Path $Core 'MessageCenter/Get-CIPPMessageCenterDigest.ps1')
    . (Join-Path $Core 'IntuneOps/Format-CIPPCentralTime.ps1')
    . (Join-Path $Core 'Tools/ConvertTo-CIPPBoolean.ps1')

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }
    $Accelerators = [PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    if (-not ('HttpStatusCode' -as [type])) {
        $Accelerators::Add('HttpStatusCode', [System.Net.HttpStatusCode])
    }
    . (Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Tenant/Reports/Invoke-ListMessageCenterDigest.ps1')

    function Get-CIPPDbItem { param($TenantFilter, $Type, [switch]$ByTenant, $Partition) }
    function Get-Tenants { param($TenantFilter, [switch]$IncludeErrors) }
    function New-GraphGetRequest { param($uri, $tenantid) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) }

    # 2026-11-01 12:00 CST (DST ended at 02:00 local that morning).
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-11-01T18:00:00', [System.DateTimeKind]::Utc)

    function New-Post {
        param(
            [string]$Id, [string]$Title, [string]$Category = 'stayInformed', [string]$Severity = 'normal',
            [string[]]$Tags = @('Admin impact'), [string[]]$Services = @('Exchange Online'), $Deadline = $null,
            $Start = '2026-01-01T00:00:00Z', $Modified = '2026-01-01T00:00:00Z', [string]$Summary = '', [bool]$Major = $false
        )
        [pscustomobject]@{
            id                       = $Id
            title                    = $Title
            category                 = $Category
            severity                 = $Severity
            tags                     = $Tags
            services                 = $Services
            isMajorChange            = $Major
            actionRequiredByDateTime = $Deadline
            startDateTime            = $Start
            lastModifiedDateTime     = $Modified
            details                  = @([pscustomobject]@{ name = 'Summary'; value = $Summary })
        }
    }

    $script:Ews = New-Post -Id 'MC1446796' -Title '(Updated) Migrate Free/Busy, MailTips, and Calendar Sharing before EWS deprecation' -Category 'planForChange' `
        -Tags @('Updated message', 'User impact', 'Admin impact', 'Retirement') -Deadline '2026-10-01T07:00:00Z' -Start '2026-08-03T22:18:34Z' -Modified '2026-10-30T16:13:46.707Z' -Major $true
    $script:Sspr = New-Post -Id 'MC1325414' -Title '(Updated) Microsoft Entra ID SSPR will require registered authentication methods starting November 9, 2026' -Category 'planForChange' `
        -Tags @('Updated message', 'User impact', 'Admin impact') -Services @('Microsoft Entra') -Deadline '2026-11-06T07:00:00Z' -Start '2026-05-01T00:00:00Z' -Modified '2026-08-04T16:34:28.88Z' -Major $true
    $script:Retire = New-Post -Id 'MC1528013' -Title 'Microsoft SharePoint: SharePoint Server access through the mobile apps will be retired' -Category 'planForChange' `
        -Tags @('User impact', 'Admin impact', 'Retirement') -Services @('SharePoint Online') -Start '2026-10-27T23:26:28Z' -Modified '2026-10-27T23:26:56Z'
    $script:QrCode = New-Post -Id 'MC1526651' -Title 'Microsoft Teams: Malicious QR code detection in messages' -Tags @('New feature', 'User impact', 'Admin impact') `
        -Services @('Microsoft Teams') -Start '2026-10-26T22:29:08Z' -Modified '2026-10-26T22:29:55Z'
    $script:Telephony = New-Post -Id 'MC1519855' -Title '(Updated) Microsoft Entra: Choose your own telephony provider now generally available' -Tags @('Updated message', 'New feature', 'Admin impact') `
        -Services @('Microsoft Entra') -Start '2026-10-21T23:24:44Z' -Modified '2026-10-30T19:34:52Z'
    $script:OptIn = New-Post -Id 'MC9000001' -Title 'Microsoft Teams: Meeting recap sharing' -Summary 'This feature is off by default. Admins can enable it in the Teams admin center.' `
        -Services @('Microsoft Teams') -Start '2026-10-28T00:00:00Z' -Modified '2026-10-28T00:00:00Z'
    $script:NotEnabled = New-Post -Id 'MC9000002' -Title 'Viva: Survey export' -Summary 'The setting will not be enabled by default.' -Services @('Microsoft Viva') `
        -Start '2026-10-28T00:00:00Z' -Modified '2026-10-28T00:00:00Z'
    $script:DefaultOn = New-Post -Id 'MC1515917' -Title 'Database Hub in Fabric: Default enablement and admin opt-out' -Category 'planForChange' -Services @('Power BI') `
        -Start '2026-10-29T00:00:00Z' -Modified '2026-10-29T00:00:00Z'
    $script:Stale = New-Post -Id 'MC1005517' -Title 'Microsoft Teams: Custom meeting branding' -Tags @('Retirement') -Start '2025-02-14T01:17:13Z' -Modified '2025-02-14T01:18:26Z'
    $script:FarDeadline = New-Post -Id 'MC1528000' -Title 'Microsoft Entra ID: Reminder to migrate from Microsoft-provided SMS and voice authentication' -Category 'planForChange' `
        -Tags @('Retirement') -Services @('Microsoft Entra') -Deadline '2027-02-01T08:00:00Z' -Start '2026-09-01T00:00:00Z' -Modified '2026-09-01T00:00:00Z'
    $script:High = New-Post -Id 'MC1526468' -Title 'Update to MC1510951: Canada 2026 time zone changes' -Category 'preventOrFixIssue' -Severity 'high' `
        -Services @('Microsoft 365 suite') -Start '2026-10-26T19:32:58Z' -Modified '2026-10-26T20:00:31Z'
}

Describe 'Get-CIPPMessageCenterClassification' {
    It 'puts a post with an act-by date in Action required and keeps the Retirement flag' {
        $C = Get-CIPPMessageCenterClassification -Message $script:Ews -Now $script:Now
        $C.Category | Should -Be 'ActionRequired'
        $C.Notify | Should -BeTrue
        $C.Flags | Should -Contain 'Retirement'
        $C.Deadline | Should -Be '2026-10-01'
        $C.DaysLeft | Should -Be -31
        $C.DeadlineStatus | Should -Be 'Overdue'
        $C.DueSoon | Should -BeFalse
    }

    It 'counts days left in US Central calendar days and marks Due soon' {
        # 2026-11-06T07:00Z is 01:00 CST on 6 November: five days after 1 November.
        $C = Get-CIPPMessageCenterClassification -Message $script:Sspr -Now $script:Now
        $C.Deadline | Should -Be '2026-11-06'
        $C.DaysLeft | Should -Be 5
        $C.DeadlineStatus | Should -Be 'Due soon'
        $C.DueSoon | Should -BeTrue
    }

    It 'honours DeadlineDays' {
        $C = Get-CIPPMessageCenterClassification -Message $script:Sspr -Now $script:Now -DeadlineDays 3
        $C.DeadlineStatus | Should -Be 'Upcoming'
        $C.DueSoon | Should -BeFalse
    }

    It 'reads [datetime] and [datetimeoffset] dates the same as ISO strings' {
        $AsDate = $script:Sspr.PSObject.Copy()
        $AsDate.actionRequiredByDateTime = [datetime]::SpecifyKind([datetime]'2026-11-06T07:00:00', [System.DateTimeKind]::Utc)
        (Get-CIPPMessageCenterClassification -Message $AsDate -Now $script:Now).DaysLeft | Should -Be 5
        $AsOffset = $script:Sspr.PSObject.Copy()
        $AsOffset.actionRequiredByDateTime = [datetimeoffset]'2026-11-06T07:00:00+00:00'
        (Get-CIPPMessageCenterClassification -Message $AsOffset -Now $script:Now).DaysLeft | Should -Be 5
    }

    It 'treats high severity as Action required' {
        (Get-CIPPMessageCenterClassification -Message $script:High -Now $script:Now).Category | Should -Be 'ActionRequired'
    }

    It 'classifies a Retirement-tagged post with no deadline as Retirement' {
        $C = Get-CIPPMessageCenterClassification -Message $script:Retire -Now $script:Now
        $C.Category | Should -Be 'Retirement'
        $C.DaysLeft | Should -BeNullOrEmpty
        $C.DeadlineStatus | Should -Be ''
    }

    It 'classifies security keywords in the title as Security' {
        $C = Get-CIPPMessageCenterClassification -Message $script:QrCode -Now $script:Now
        $C.Category | Should -Be 'Security'
        $C.Notify | Should -BeTrue
    }

    It 'does not treat an Entra stayInformed feature post as Security' {
        $C = Get-CIPPMessageCenterClassification -Message $script:Telephony -Now $script:Now
        $C.Category | Should -Be 'Informational'
        $C.Notify | Should -BeFalse
    }

    It 'ignores the Admin impact tag on its own' {
        $Plain = New-Post -Id 'MC1' -Title 'Outlook: Reply With a Template in Rules' -Tags @('Admin impact', 'User impact')
        (Get-CIPPMessageCenterClassification -Message $Plain -Now $script:Now).Category | Should -Be 'Informational'
    }

    It 'reads opt-in wording from the summary and never notifies' {
        $C = Get-CIPPMessageCenterClassification -Message $script:OptIn -Now $script:Now
        $C.Category | Should -Be 'OptIn'
        $C.Notify | Should -BeFalse
    }

    It 'treats "not enabled by default" as opt-in only, not as a default change' {
        $C = Get-CIPPMessageCenterClassification -Message $script:NotEnabled -Now $script:Now
        $C.Category | Should -Be 'OptIn'
        $C.Flags | Should -Not -Contain 'DefaultChange'
    }

    It 'classifies default enablement with admin opt-out as DefaultChange' {
        $C = Get-CIPPMessageCenterClassification -Message $script:DefaultOn -Now $script:Now
        $C.Category | Should -Be 'DefaultChange'
        $C.Notify | Should -BeFalse
    }
}

Describe 'Get-CIPPMessageCenterDigest' {
    BeforeEach {
        Mock Get-CIPPDbItem { [ordered]@{} }
        Mock Get-Tenants { }
        Mock New-GraphGetRequest { @() }
    }

    It 'dedupes by MC id, keeps the newest copy and lists every tenant' {
        $Older = $script:Retire.PSObject.Copy()
        $Older.title = 'Old title'
        $Older.lastModifiedDateTime = '2026-10-27T00:00:00Z'
        $Supplied = [ordered]@{
            'b.com' = @($script:Retire)
            'a.com' = @($Older, $script:QrCode)
        }
        $D = Get-CIPPMessageCenterDigest -TenantFilter 'AllTenants' -MessagesByTenant $Supplied -Now $script:Now
        $Item = $D.Items | Where-Object MessageId -EQ 'MC1528013'
        @($Item).Count | Should -Be 1
        $Item.Title | Should -Be $script:Retire.title
        $Item.Tenants | Should -Be @('a.com', 'b.com')
        $Item.TenantCount | Should -Be 2
        $Item.TenantsText | Should -Be 'a.com, b.com'
        $Item.Link | Should -Be 'https://admin.microsoft.com/#/MessageCenter/:/messages/MC1528013'
        $D.Summary.PostsRead | Should -Be 2
        $D.Summary.TenantsCovered | Should -Be 2
        Should -Invoke Get-CIPPDbItem -Times 0
    }

    It 'keeps posts in the window or due soon, drops stale and informational ones' {
        $Supplied = [ordered]@{ 'a.com' = @($script:Ews, $script:Sspr, $script:Stale, $script:Telephony, $script:FarDeadline, $script:OptIn) }
        $D = Get-CIPPMessageCenterDigest -TenantFilter 'a.com' -MessagesByTenant $Supplied -Now $script:Now
        $Ids = @($D.Items.MessageId)
        $Ids | Should -Contain 'MC1446796'
        $Ids | Should -Contain 'MC1325414'
        $Ids | Should -Contain 'MC9000001'
        $Ids | Should -Not -Contain 'MC1005517'
        $Ids | Should -Not -Contain 'MC1519855'
        $Ids | Should -Not -Contain 'MC1528000'
        ($D.Items | Where-Object MessageId -EQ 'MC1446796').WindowReason | Should -Be 'Updated'
        ($D.Items | Where-Object MessageId -EQ 'MC1325414').WindowReason | Should -Be 'Deadline approaching'
        ($D.Items | Where-Object MessageId -EQ 'MC9000001').WindowReason | Should -Be 'New'
        $D.Summary.DueSoon | Should -Be 1
        $D.Summary.Overdue | Should -Be 1
    }

    It 'includes informational posts on request and open deadlines with -IncludeOpenDeadlines' {
        $Supplied = [ordered]@{ 'a.com' = @($script:Telephony, $script:FarDeadline) }
        $D = Get-CIPPMessageCenterDigest -TenantFilter 'a.com' -MessagesByTenant $Supplied -Now $script:Now -IncludeInformational -IncludeOpenDeadlines
        ($D.Items | Where-Object MessageId -EQ 'MC1519855').Category | Should -Be 'Informational'
        ($D.Items | Where-Object MessageId -EQ 'MC1528000').WindowReason | Should -Be 'Open deadline'
    }

    It 'sorts alerting categories first, nearest deadline first' {
        $Supplied = [ordered]@{ 'a.com' = @($script:OptIn, $script:Retire, $script:Sspr, $script:Ews) }
        $D = Get-CIPPMessageCenterDigest -TenantFilter 'a.com' -MessagesByTenant $Supplied -Now $script:Now
        @($D.Items.MessageId) | Should -Be @('MC1446796', 'MC1325414', 'MC1528013', 'MC9000001')
    }

    It 'reads AllTenants from the cache and lists managed tenants with nothing cached' {
        Mock Get-CIPPDbItem {
            [ordered]@{
                'a.com' = [System.Collections.Generic.List[object]]@(
                    [pscustomobject]@{ PartitionKey = 'a.com'; Timestamp = [datetimeoffset]'2026-11-01T08:04:08Z'; Data = (ConvertTo-Json -InputObject $script:Retire -Depth 5 -Compress) }
                )
                'b.com' = [System.Collections.Generic.List[object]]@(
                    [pscustomobject]@{ PartitionKey = 'b.com'; Timestamp = [datetimeoffset]'2026-11-01T08:03:29Z'; Data = (ConvertTo-Json -InputObject $script:Retire -Depth 5 -Compress) }
                )
            }
        }
        Mock Get-Tenants { @([pscustomobject]@{ defaultDomainName = 'a.com' }, [pscustomobject]@{ defaultDomainName = 'b.com' }, [pscustomobject]@{ defaultDomainName = 'c.com' }) }
        $D = Get-CIPPMessageCenterDigest -TenantFilter 'AllTenants' -Now $script:Now
        $D.Summary.Source | Should -Be 'Cache'
        $D.Summary.NotCached | Should -Be @('c.com')
        @($D.Items).Count | Should -Be 1
        $D.Items[0].TenantCount | Should -Be 2
        $D.Summary.OldestCache | Should -Match '^2026-11-01 0[23]:03 C[SD]T \(08:03 UTC\)$'
        Should -Invoke Get-CIPPDbItem -Times 1 -ParameterFilter { $TenantFilter -eq 'allTenants' -and $Type -eq 'MessageCenterMessages' -and $ByTenant }
        Should -Invoke New-GraphGetRequest -Times 0
    }

    It 'throws for AllTenants when nothing is cached' {
        Mock Get-Tenants { @([pscustomobject]@{ defaultDomainName = 'a.com' }) }
        { Get-CIPPMessageCenterDigest -TenantFilter 'AllTenants' -Now $script:Now } | Should -Throw '*No Message Center posts are cached*'
    }

    It 'falls back to live Graph for a single tenant with nothing cached' {
        Mock New-GraphGetRequest { @($script:QrCode) }
        $D = Get-CIPPMessageCenterDigest -TenantFilter 'a.com' -Now $script:Now
        $D.Summary.Source | Should -Be 'Live'
        $D.Items[0].MessageId | Should -Be 'MC1526651'
        Should -Invoke New-GraphGetRequest -Times 1 -ParameterFilter { $uri -eq 'https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/messages' -and $tenantid -eq 'a.com' }
    }
}

Describe 'Invoke-ListMessageCenterDigest' {
    BeforeEach {
        Mock Write-LogMessage {}
        Mock Get-CIPPMessageCenterDigest { [pscustomobject]@{ Items = @(); Summary = [pscustomobject]@{ Total = 0 }; Errors = @() } }
    }

    It 'passes defaults and does not read "false" as true' {
        $Request = [pscustomobject]@{ Params = @{ CIPPEndpoint = 'ListMessageCenterDigest' }; Headers = @{}; Query = [pscustomobject]@{ tenantFilter = 'AllTenants'; includeInformational = 'false' } }
        $Response = Invoke-ListMessageCenterDigest -Request $Request
        $Response.StatusCode | Should -Be 200
        Should -Invoke Get-CIPPMessageCenterDigest -Times 1 -ParameterFilter { $TenantFilter -eq 'AllTenants' -and $Days -eq 7 -and $DeadlineDays -eq 30 -and -not $IncludeInformational }
    }

    It 'passes days, deadlineDays and includeInformational through' {
        $Request = [pscustomobject]@{ Params = @{ CIPPEndpoint = 'ListMessageCenterDigest' }; Headers = @{}; Query = [pscustomobject]@{ tenantFilter = 'a.com'; days = '14'; deadlineDays = '60'; includeInformational = 'true' } }
        Invoke-ListMessageCenterDigest -Request $Request | Out-Null
        Should -Invoke Get-CIPPMessageCenterDigest -Times 1 -ParameterFilter { $TenantFilter -eq 'a.com' -and $Days -eq 14 -and $DeadlineDays -eq 60 -and $IncludeInformational }
    }

    It 'rejects a missing tenantFilter' {
        $Request = [pscustomobject]@{ Params = @{ CIPPEndpoint = 'ListMessageCenterDigest' }; Headers = @{}; Query = [pscustomobject]@{} }
        (Invoke-ListMessageCenterDigest -Request $Request).StatusCode | Should -Be 400
        Should -Invoke Get-CIPPMessageCenterDigest -Times 0
    }

    It 'returns 500 with the reason when the digest cannot be built' {
        Mock Get-CIPPMessageCenterDigest { throw 'No Message Center posts are cached for any tenant yet.' }
        $Request = [pscustomobject]@{ Params = @{ CIPPEndpoint = 'ListMessageCenterDigest' }; Headers = @{}; Query = [pscustomobject]@{ tenantFilter = 'AllTenants' } }
        $Response = Invoke-ListMessageCenterDigest -Request $Request
        $Response.StatusCode | Should -Be 500
        $Response.Body.Results | Should -Match 'No Message Center posts are cached'
    }
}
