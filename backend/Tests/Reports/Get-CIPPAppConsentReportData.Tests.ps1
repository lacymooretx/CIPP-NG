# The App Consent Posture Report. The assertions that matter are the ones encoding what CW #58402
# taught: a tenant with the request workflow off is a FAIL (users hit a dead end and nobody is
# told), Microsoft-managed consent mode must be called out (the assignment is read-only through the
# API, so per-app consent is the only route), and an Expired request must be reported because it is
# one somebody made and nobody answered.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPCore/Public/Reports/Get-CIPPAppConsentReportData.ps1'

    function Get-Tenants { param($TenantFilter) [pscustomobject]@{ customerId = 'cust-0001' } }
    function New-GraphGetRequest {
        param($uri, $tenantid, $noPagination)
        switch -Regex ($uri) {
            '/organization$' { return @([pscustomobject]@{ displayName = 'Contoso'; verifiedDomains = @([pscustomobject]@{ name = 'contoso.com'; isDefault = $true }) }) }
            'adminConsentRequestPolicy' { return $script:ConsentPolicy }
            'authorizationPolicy' { return $script:AuthPolicy }
            'auditLogs/signIns' { return $script:SignIns }
            '/userConsentRequests$' { return $script:Children }
            'appConsentRequests$' { return $script:Requests }
        }
        return @()
    }

    . $FunctionPath

    function Get-Section { param($Model, $Title) $Model.Sections | Where-Object { $_.Title -eq $Title } }
    function Get-FindingStatus { param($Model, $Match) ($Model.Findings | Where-Object { $_.Title -match $Match }).Status }
}

Describe 'Get-CIPPAppConsentReportData' {
    BeforeEach {
        $script:ConsentPolicy = [pscustomobject]@{ isEnabled = $true; notifyReviewers = $true; reviewers = @(1); requestDurationInDays = 30 }
        $script:AuthPolicy = [pscustomobject]@{ permissionGrantPolicyIdsAssignedToDefaultUserRole = @('ManagePermissionGrantsForSelf.cipp-consent-policy') }
        $script:SignIns = @()
        $script:Requests = @()
        $script:Children = @()
    }

    It 'returns the model shape the renderer expects' {
        $m = Get-CIPPAppConsentReportData -TenantFilter 'contoso.com'

        # Mismatched keys here render a broken report rather than failing loudly.
        $m.Keys | Should -Contain 'Title'
        $m.Keys | Should -Contain 'TenantName'
        $m.Keys | Should -Contain 'TenantDomain'
        $m.Keys | Should -Contain 'GeneratedDate'
        $m.Title | Should -Be 'App Consent Posture Report'
        $m.TenantName | Should -Be 'Contoso'
        $m.TenantDomain | Should -Be 'contoso.com'
    }

    It 'fails the tenant when users cannot request consent at all' {
        $script:ConsentPolicy = [pscustomobject]@{ isEnabled = $false; notifyReviewers = $false; reviewers = @(); requestDurationInDays = 30 }

        $m = Get-CIPPAppConsentReportData -TenantFilter 'contoso.com'

        (Get-Section $m 'Admin Consent Request Workflow').Status | Should -Be 'fail'
        Get-FindingStatus $m 'cannot request admin consent' | Should -Be 'fail'
    }

    It 'warns when the workflow is on but nobody is assigned to review' {
        $script:ConsentPolicy = [pscustomobject]@{ isEnabled = $true; notifyReviewers = $true; reviewers = @(); requestDurationInDays = 30 }

        $m = Get-CIPPAppConsentReportData -TenantFilter 'contoso.com'

        Get-FindingStatus $m 'no reviewers' | Should -Be 'warn'
    }

    It 'identifies Microsoft-managed consent mode by its policy pair' {
        $script:AuthPolicy = [pscustomobject]@{ permissionGrantPolicyIdsAssignedToDefaultUserRole = @(
                'ManagePermissionGrantsForSelf.microsoft-user-default-recommended'
                'ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps'
            ) }

        $m = Get-CIPPAppConsentReportData -TenantFilter 'contoso.com'

        (Get-Section $m 'User Consent Policy').Status | Should -Be 'warn'
        Get-FindingStatus $m 'Microsoft-managed' | Should -Be 'warn'
    }

    It 'does not call an explicitly configured tier Microsoft-managed' {
        $m = Get-CIPPAppConsentReportData -TenantFilter 'contoso.com'

        (Get-Section $m 'User Consent Policy').Status | Should -Be 'pass'
        Get-FindingStatus $m 'Microsoft-managed' | Should -BeNullOrEmpty
    }

    It 'groups blocked sign-ins per application with a consent URL' {
        $script:SignIns = @(
            [pscustomobject]@{ createdDateTime = '2026-09-16T21:00:00Z'; userPrincipalName = 'amber@contoso.com'; appDisplayName = 'Granola'; appId = 'app-1'; status = [pscustomobject]@{ errorCode = 90094 } }
            [pscustomobject]@{ createdDateTime = '2026-09-17T18:44:00Z'; userPrincipalName = 'blair@contoso.com'; appDisplayName = 'Granola'; appId = 'app-1'; status = [pscustomobject]@{ errorCode = 90094 } }
        )

        $m = Get-CIPPAppConsentReportData -TenantFilter 'contoso.com'
        $Section = Get-Section $m 'Blocked Sign-ins (last 30 days)'

        $Section.Rows | Should -HaveCount 1
        $Section.Rows[0][0] | Should -Be 'Granola'
        $Section.Rows[0][2] | Should -Be '2'   # distinct users
        $Section.Rows[0][3] | Should -Be '2'   # attempts
        $Section.Rows[0][5] | Should -Be 'https://login.microsoftonline.com/cust-0001/adminconsent?client_id=app-1'
        Get-FindingStatus $m 'blocked by consent' | Should -Be 'warn'
    }

    It 'passes the section when nobody was blocked' {
        $m = Get-CIPPAppConsentReportData -TenantFilter 'contoso.com'

        (Get-Section $m 'Blocked Sign-ins (last 30 days)').Status | Should -Be 'pass'
    }

    It 'reports a request that expired unanswered' {
        $script:Requests = @([pscustomobject]@{ id = 'r1'; appId = 'app-9'; appDisplayName = 'Summary AI'; pendingScopes = @() })
        $script:Children = @([pscustomobject]@{ id = 'u1'; reason = 'Need it'; status = 'Expired'; createdDateTime = '2026-08-09T22:26:39Z'; createdBy = [pscustomobject]@{ user = [pscustomobject]@{ userPrincipalName = 'lacy@contoso.com' } } })

        $m = Get-CIPPAppConsentReportData -TenantFilter 'contoso.com'

        Get-FindingStatus $m 'expired unanswered' | Should -Be 'warn'
        (Get-Section $m 'Consent Requests').Rows[0][3] | Should -Be 'Expired'
    }

    It 'degrades one section rather than the whole report when a call fails' {
        Mock New-GraphGetRequest { if ($uri -match 'adminConsentRequestPolicy') { throw 'boom' } return @() } -ParameterFilter { $true }

        { Get-CIPPAppConsentReportData -TenantFilter 'contoso.com' } | Should -Not -Throw
        $m = Get-CIPPAppConsentReportData -TenantFilter 'contoso.com'
        (Get-Section $m 'Admin Consent Request Workflow').Status | Should -Be 'warn'
    }
}
