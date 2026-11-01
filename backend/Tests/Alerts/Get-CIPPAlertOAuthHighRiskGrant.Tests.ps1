# Aspendora fork (Vikunja CIPP-11): high-risk OAuth grant alert, with the collector stubbed.
BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertOAuthHighRiskGrant.ps1')

    function Get-CIPPOAuthGrantRisk { param($TenantFilter) if ($script:Throw) { throw 'Authorization_RequestDenied' }; [pscustomobject]@{ Apps = $script:Apps } }
    function Get-CIPPTextReplacement { param($TenantFilter, $Text) $Text -replace '%oauthallowlist%', 'Backup Application *' }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev) $script:Logs.Add($message) }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data) $script:Traced++; $script:Data = @($data); $data }
    function Get-Tenants { param($TenantFilter) [pscustomobject]@{ defaultDomainName = $TenantFilter; customerId = '11111111-2222-3333-4444-555555555555' } }

    function script:New-App {
        param($Name, $Risk, $High = @(), $Data = @(), $Ai = $null, [bool]$Microsoft = $false, $Score = 100)
        [pscustomobject]@{
            DisplayName = $Name; AppId = "id-$($Name -replace ' ', '')"; Publisher = 'Vendor'; PublisherVerified = $false; IsMicrosoft = $Microsoft
            Risk = $Risk; Score = $Score; HighRiskPermissions = @($High); DataPermissions = @($Data); IsAiConnector = [bool]$Ai; AiTool = $Ai
            ConsentScope = 'App-only'; BlastRadius = 'Can read every mailbox in the tenant, without a user signed in.'; Reasons = @('App-only.')
            SuggestedAction = 'disable the service principal (accountEnabled=false)'; SignInKnown = $true; LastSignIn = [datetime]::new(2026, 10, 30, 12, 0, 0, [System.DateTimeKind]::Utc)
        }
    }
}

Describe 'Get-CIPPAlertOAuthHighRiskGrant' {
    BeforeEach {
        $script:Logs = [System.Collections.Generic.List[string]]::new()
        $script:Traced = 0; $script:Data = $null; $script:Throw = $false
        $script:Apps = @(
            New-App 'Backup Application 1234' 'Critical' -High @('full_access_as_app') -Data @('full_access_as_app')
            New-App 'Evil Mail Reader' 'High' -High @('Mail.Read') -Data @('Mail.Read') -Score 85
            New-App 'Some Medium App' 'Medium' -High @('Mail.Read') -Data @('Mail.Read') -Score 32
            New-App 'Otter Notes' 'Medium' -High @('Files.Read.All') -Data @('Files.Read.All') -Ai 'Otter.ai' -Score 47
            New-App 'Exchange Online Protection' 'Low' -Microsoft $true -Score 0
        )
    }

    It 'raises Critical/High apps and AI connectors with data scopes, not Medium or Microsoft apps' {
        $R = @(Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'contoso.com')
        $R.App | Should -Be @('Backup Application 1234', 'Evil Mail Reader', 'Otter Notes')
        $R[0].Severity | Should -Be 'Critical'
        $R[0].Id | Should -Be 'id-BackupApplication1234|full_access_as_app'
        $R[0].BlastRadius | Should -Match 'every mailbox'
        $R[0].SuggestedAction | Should -Match 'accountEnabled=false'
        $R[0].Publisher | Should -Be 'Vendor (unverified)'
        $R[0].LastSignIn | Should -Be '2026-10-30'
        $R[2].AiTool | Should -Be 'Otter.ai'
    }

    It 'skips allow-listed apps by appId, exact name or wildcard, and expands custom variables' {
        $R = @(Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'contoso.com' -InputValue @{ OAuthRiskAllowList = '%oauthallowlist%, id-EvilMailReader' })
        $R.App | Should -Be @('Otter Notes')
        $R = @(Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'contoso.com' -InputValue @{ OAuthRiskAllowList = 'otter notes' })
        $R.App | Should -Be @('Backup Application 1234', 'Evil Mail Reader')
    }

    It 'applies tenant-specific entries only to that tenant (domain or tenant id)' {
        $In = @{ OAuthRiskAllowList = 'Backup Application *'; OAuthRiskTenantAllowList = 'contoso.com|id-EvilMailReader, fabrikam.com|Otter Notes' }
        @(Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'contoso.com' -InputValue $In).App | Should -Be @('Otter Notes')
        @(Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'fabrikam.com' -InputValue $In).App | Should -Be @('Evil Mail Reader')
        @(Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'other.com' -InputValue $In).App | Should -Be @('Evil Mail Reader', 'Otter Notes')
        $ById = @{ OAuthRiskTenantAllowList = "11111111-2222-3333-4444-555555555555|Evil *`nCONTOSO.COM|otter notes" }
        @(Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'contoso.com' -InputValue $ById).App | Should -Be @('Backup Application 1234')
    }

    It 'scopes a tenant|entry found in the fleet-wide list, and ignores malformed entries' {
        $In = @{ OAuthRiskAllowList = 'Backup Application *, fabrikam.com|id-EvilMailReader, |Otter Notes, contoso.com|' }
        @(Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'contoso.com' -InputValue $In).App | Should -Be @('Evil Mail Reader', 'Otter Notes')
        @(Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'fabrikam.com' -InputValue $In).App | Should -Be @('Otter Notes')
    }

    It 'keys each row on appId plus scope set, so a new scope notifies again' {
        $First = @(Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'contoso.com')[1].Id
        $script:Apps[1].HighRiskPermissions = @('Mail.Read', 'Mail.Send')
        $script:Apps[1].DataPermissions = @('Mail.Read', 'Mail.Send')
        $Second = @(Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'contoso.com')[1].Id
        $First | Should -Be 'id-EvilMailReader|Mail.Read'
        $Second | Should -Be 'id-EvilMailReader|Mail.Read,Mail.Send'
    }

    It 'reconciles an empty result so resolved grants clear' {
        $script:Apps = @(New-App 'Fine App' 'Low' -Score 0)
        Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'contoso.com' | Should -BeNullOrEmpty
        $script:Traced | Should -Be 1
        $script:Data.Count | Should -Be 0
    }

    It 'does not reconcile when the grants could not be read' {
        $script:Throw = $true
        Get-CIPPAlertOAuthHighRiskGrant -TenantFilter 'contoso.com' | Should -BeNullOrEmpty
        $script:Traced | Should -Be 0
        $script:Logs[0] | Should -Match 'OAuth high-risk grant check failed'
    }
}
