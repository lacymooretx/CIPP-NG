# The consent standards must not report success for a write that did nothing.
#
# A tenant in Microsoft-managed consent mode ("Let Microsoft manage your consent settings") does not
# own permissionGrantPolicyIdsAssignedToDefaultUserRole - Microsoft does. A PATCH against it is
# accepted, answered 204 and discarded. Verified live on Blair's Solar Filming (CW #58402); root
# cause in docs/todo-cipp-bugs.md 5b.
#
# UndoOauth had no post-remediation read at all, so it logged success AND left $StateIsCorrect at
# its pre-remediation value, which the alert and report then reported. OauthConsent did re-read, but
# logged its success line unconditionally. Both are covered here.
#
# The managed-mode fingerprint is the pair: microsoft-user-default-recommended +
# microsoft-user-default-allow-consent-apps.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $UndoPath = Join-Path $RepoRoot 'Modules/CIPPStandards/Public/Standards/Invoke-CIPPStandardUndoOauth.ps1'

    $script:ManagedMode = @(
        'ManagePermissionGrantsForSelf.microsoft-user-default-recommended'
        'ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps'
    )

    function New-GraphGetRequest {
        param($uri, $tenantid, $Uri2)
        return [pscustomobject]@{ permissionGrantPolicyIdsAssignedToDefaultUserRole = $script:CurrentAssigned }
    }
    function New-GraphPostRequest {
        param($tenantid, $uri, $AsApp, $Type, $ContentType, $Body)
        $script:PostCalled = $true
        # The behaviour under test: accepted, and silently ignored.
        if (-not $script:WriteApplies) { return $null }
        $script:CurrentAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy')
        return $null
    }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) $script:Logs += @([pscustomobject]@{ Message = $message; Sev = $sev }) }
    function Write-StandardsAlert { param($message, $object, $tenant, $standardName, $standardId) $script:Alerts += @($message) }
    function Get-NormalizedError { param($Message) $Message }
    function Set-CIPPStandardsCompareField { param($FieldName, $FieldValue, $TenantFilter) $script:ReportedField = $FieldValue }
    function Add-CIPPBPAField { param($FieldName, $FieldValue, $StoreAs, $Tenant) $script:ReportedField = $FieldValue }
    function Get-CIPPStandards { param($Tenant) @() }

    . $UndoPath
}

Describe 'UndoOauth read-back' {
    BeforeEach {
        $script:Logs = @()
        $script:Alerts = @()
        $script:PostCalled = $false
        $script:ReportedField = $null
        $script:CurrentAssigned = $script:ManagedMode
    }

    It 'logs an ERROR naming managed mode when the write is silently discarded' {
        $script:WriteApplies = $false

        Invoke-CIPPStandardUndoOauth -Tenant 'contoso.com' -Settings ([pscustomobject]@{ remediate = $true })

        $script:PostCalled | Should -BeTrue
        $Errors = @($script:Logs | Where-Object { $_.Sev -eq 'Error' })
        $Errors | Should -Not -BeNullOrEmpty
        $Errors[0].Message | Should -Match 'could NOT be disabled'
        $Errors[0].Message | Should -Match 'Microsoft-managed consent mode'
        # The old behaviour - the thing this test exists to prevent.
        @($script:Logs | Where-Object { $_.Message -match 'has been disabled' }) | Should -BeNullOrEmpty
    }

    It 'still reports the tenant as non-compliant after a discarded write' {
        # The real damage: $StateIsCorrect kept its pre-remediation value, so alert and report
        # agreed the standard had been applied.
        $script:WriteApplies = $false

        Invoke-CIPPStandardUndoOauth -Tenant 'contoso.com' -Settings ([pscustomobject]@{ remediate = $true; alert = $true })

        $script:Alerts | Should -Not -BeNullOrEmpty
        $script:Alerts[0] | Should -Match 'not disabled'
    }

    It 'logs success and reports compliant when the write really applies' {
        $script:WriteApplies = $true

        Invoke-CIPPStandardUndoOauth -Tenant 'contoso.com' -Settings ([pscustomobject]@{ remediate = $true; alert = $true })

        @($script:Logs | Where-Object { $_.Message -match 'has been disabled' }) | Should -Not -BeNullOrEmpty
        @($script:Logs | Where-Object { $_.Sev -eq 'Error' }) | Should -BeNullOrEmpty
        $script:Alerts | Should -BeNullOrEmpty
    }

    It 'distinguishes a plain failed write from managed mode' {
        # Not the managed-mode pair, and the value still did not move.
        $script:CurrentAssigned = @('ManagePermissionGrantsForSelf.cipp-consent-policy')
        $script:WriteApplies = $false

        Invoke-CIPPStandardUndoOauth -Tenant 'contoso.com' -Settings ([pscustomobject]@{ remediate = $true })

        $Errors = @($script:Logs | Where-Object { $_.Sev -eq 'Error' })
        $Errors[0].Message | Should -Match 'did not change'
        $Errors[0].Message | Should -Not -Match 'Microsoft-managed'
    }

    It 'does not write at all when the tenant is already compliant' {
        $script:CurrentAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy')
        $script:WriteApplies = $true

        Invoke-CIPPStandardUndoOauth -Tenant 'contoso.com' -Settings ([pscustomobject]@{ remediate = $true })

        $script:PostCalled | Should -BeFalse
        @($script:Logs | Where-Object { $_.Message -match 'already disabled' }) | Should -Not -BeNullOrEmpty
    }
}
