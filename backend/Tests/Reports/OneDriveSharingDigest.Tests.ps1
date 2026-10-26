# Pester tests for the OneDrive sharing digest (Aspendora fork): per-owner grouping and risk order,
# the rendered email, and the preview/live gate in Push-ExecOneDriveSharingDigest.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Dir = Join-Path $RepoRoot 'Modules/CIPPCore/Public/SharingLinks'
    . (Join-Path $Dir 'Get-CIPPOneDriveSharingDigest.ps1')
    . (Join-Path $Dir 'New-CIPPOneDriveSharingDigestHtml.ps1')
    . (Join-Path $Dir 'Push-ExecOneDriveSharingDigest.ps1')

    # Static stubs. No pass-through mocks.
    function Get-CIPPSharingLinks {
        param($TenantFilter)
        @(
            [pscustomobject]@{ workload = 'OneDrive'; siteId = 's1'; siteName = 'Ann'; fileName = 'b-internal.docx'; itemUrl = 'https://x/b'; itemType = 'File'; classification = 'Internal'; linkScope = 'organization'; roles = @('read'); sharedWith = @() }
            [pscustomobject]@{ workload = 'OneDrive'; siteId = 's1'; siteName = 'Ann'; fileName = 'a-anon-view.xlsx'; itemUrl = 'https://x/a'; itemType = 'File'; classification = 'Anonymous'; linkScope = 'anonymous'; roles = @('read'); sharedWith = @(); expirationDateTime = '2026-12-01T00:00:00Z' }
            [pscustomobject]@{ workload = 'OneDrive'; siteId = 's1'; siteName = 'Ann'; fileName = 'z-anon-edit'; itemUrl = 'https://x/z'; itemType = 'Folder'; classification = 'Anonymous'; linkScope = 'anonymous'; roles = @('write'); sharedWith = @() }
            [pscustomobject]@{ workload = 'OneDrive'; siteId = 's1'; siteName = 'Ann'; fileName = 'ext.pdf'; itemUrl = 'https://x/e'; itemType = 'File'; classification = 'External'; linkScope = 'users'; roles = @('read'); sharedWith = @('guest@other.com', '') }
            [pscustomobject]@{ workload = 'OneDrive'; siteId = 's2'; siteName = 'Gone'; fileName = 'orphan.txt'; itemType = 'File'; classification = 'Internal'; linkScope = 'users'; roles = @('read'); sharedWith = @('bob@contoso.com') }
            [pscustomobject]@{ workload = 'SharePoint'; siteId = 's3'; siteName = 'Sales'; fileName = 'not-onedrive'; classification = 'Anonymous'; linkScope = 'anonymous'; roles = @('read') }
        )
    }
    function Get-Tenants { param($TenantFilter, [switch]$IncludeErrors) [pscustomobject]@{ defaultDomainName = $TenantFilter; displayName = 'Contoso' } }
    function ConvertTo-CIPPODataFilterValue { param($Value, $Type) $Value }
    function Get-CippTable { param($tablename) @{ TableName = $tablename } }
    function Get-CIPPAzDataTableEntity {
        param($TableName, $Filter)
        if ($TableName -eq 'CippSharingLinksState') { [pscustomobject]@{ CompletedUtc = $script:CompletedUtc } }
    }
    function New-GraphBulkRequest {
        param($tenantid, $Requests, $asapp)
        foreach ($Request in $Requests) {
            if ($Request.url -like 'sites/s1/drive*') { @{ id = $Request.id; status = 200; body = @{ owner = @{ user = @{ id = 'u1' } }; webUrl = 'https://contoso-my.sharepoint.com/personal/ann/Documents' } } }
            elseif ($Request.url -like 'sites/*') { @{ id = $Request.id; status = 404; body = @{} } }
            elseif ($Request.url -like 'users/u1*') { @{ id = 'u1'; status = 200; body = @{ id = 'u1'; displayName = 'Ann Smith'; givenName = 'Ann'; mail = 'ann@contoso.com'; userPrincipalName = 'ann@contoso.com'; accountEnabled = $true } } }
        }
    }
    function Get-CIPPOneDriveSharingDigestSettings {
        param($TenantFilter)
        [pscustomobject]@{ SenderMailbox = 'help@aspendora.com'; SenderTenant = 'aspendora.com'; PreviewRecipient = 'lacy@aspendora.com'; Tenant = $TenantFilter; Live = $script:Live }
    }
    function Send-CIPPOneDriveSharingDigestMail { param($Settings, $To, $Subject, $Html) $script:SentMail.Add([pscustomobject]@{ To = $To; Subject = $Subject }) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData, $headers) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$Exception" } }
    function Start-Sleep { param($Milliseconds) }
}

Describe 'Get-CIPPOneDriveSharingDigest' {
    BeforeAll {
        $script:CompletedUtc = [DateTimeOffset]::UtcNow.AddDays(-1).ToString('o')
        $script:Digest = Get-CIPPOneDriveSharingDigest -TenantFilter 'contoso.com'
    }

    It 'groups OneDrive links by the resolved owner and ignores SharePoint' {
        @($script:Digest.Users).Count | Should -Be 1
        $script:Digest.Users[0].Mail | Should -Be 'ann@contoso.com'
        (@($script:Digest.Users[0].Outside).Count + @($script:Digest.Users[0].Inside).Count) | Should -Be 4
    }

    It 'reports OneDrives whose owner cannot be resolved' {
        @($script:Digest.Unresolved).Count | Should -Be 1
        $script:Digest.Unresolved[0].siteName | Should -Be 'Gone'
    }

    It 'puts anonymous edit first, then anonymous view, then external' {
        $Outside = @($script:Digest.Users[0].Outside)
        $Outside.Name | Should -Be @('z-anon-edit', 'a-anon-view.xlsx', 'ext.pdf')
        $Outside[0].Access | Should -Be 'Can edit'
        $Outside[2].Recipients | Should -Be @('guest@other.com')
    }

    It 'keeps internal links in Inside' {
        @($script:Digest.Users[0].Inside).Name | Should -Be @('b-internal.docx')
    }
}

Describe 'New-CIPPOneDriveSharingDigestHtml' {
    BeforeAll {
        $script:CompletedUtc = [DateTimeOffset]::UtcNow.AddDays(-1).ToString('o')
        $User = (Get-CIPPOneDriveSharingDigest -TenantFilter 'contoso.com').Users[0]
        $script:Email = New-CIPPOneDriveSharingDigestHtml -User $User -CompanyName 'Contoso & Co'
    }

    It 'counts outside links in the subject' {
        $script:Email.Subject | Should -Be 'Your OneDrive sharing: 3 links reach outside Contoso & Co'
    }

    It 'flags anyone-can-edit and never-expiring links' {
        $script:Email.Html | Should -Match 'Anyone can edit'
        $script:Email.Html | Should -Match 'Never expires'
        $script:Email.Html | Should -Match '1 link lets <strong>anyone</strong>'
    }

    It 'HTML-encodes tenant-supplied text' {
        $script:Email.Html | Should -Match 'Contoso &amp; Co'
        $script:Email.Html | Should -Not -Match 'Contoso & Co'
    }

    It 'links to the OneDrive Shared view when the list is capped' {
        $User = (Get-CIPPOneDriveSharingDigest -TenantFilter 'contoso.com').Users[0]
        $Capped = New-CIPPOneDriveSharingDigestHtml -User $User -CompanyName 'Contoso' -MaxOutsideRows 1
        $Capped.Html | Should -Match 'And 2 more'
        $Capped.Html | Should -Match 'https://contoso-my.sharepoint.com/my\?v=shared'
    }
}

Describe 'Push-ExecOneDriveSharingDigest' {
    BeforeEach {
        $script:SentMail = [System.Collections.Generic.List[object]]::new()
        $script:CompletedUtc = [DateTimeOffset]::UtcNow.AddDays(-1).ToString('o')
    }

    It 'sends to the preview recipient while the tenant is not live' {
        $script:Live = $false
        $Run = Push-ExecOneDriveSharingDigest -TenantFilter 'contoso.com'
        $script:SentMail.Count | Should -Be 1
        $script:SentMail[0].To | Should -Be 'lacy@aspendora.com'
        $script:SentMail[0].Subject | Should -Match '^\[Preview for ann@contoso.com\]'
        $Run.Mode | Should -Be 'preview to lacy@aspendora.com'
    }

    It 'sends to the user once the tenant is live' {
        $script:Live = $true
        $null = Push-ExecOneDriveSharingDigest -TenantFilter 'contoso.com'
        $script:SentMail[0].To | Should -Be 'ann@contoso.com'
        $script:SentMail[0].Subject | Should -Not -Match 'Preview'
    }

    It 'a PreviewRecipient overrides a live tenant' {
        $script:Live = $true
        $null = Push-ExecOneDriveSharingDigest -TenantFilter 'contoso.com' -PreviewRecipient 'qa@aspendora.com'
        $script:SentMail[0].To | Should -Be 'qa@aspendora.com'
    }

    It 'refuses a live send on stale scan data' {
        $script:Live = $true
        $script:CompletedUtc = [DateTimeOffset]::UtcNow.AddDays(-20).ToString('o')
        $Run = Push-ExecOneDriveSharingDigest -TenantFilter 'contoso.com'
        $script:SentMail.Count | Should -Be 0
        $Run.Results | Should -Match 'finished 20 days ago'
    }

    It 'a dry run renders but sends nothing' {
        $script:Live = $true
        $Run = Push-ExecOneDriveSharingDigest -TenantFilter 'contoso.com' -DryRun $true
        $script:SentMail.Count | Should -Be 0
        @($Run.Emails).Count | Should -Be 1
        $Run.Emails[0].Html | Should -Match '<html>'
    }
}
