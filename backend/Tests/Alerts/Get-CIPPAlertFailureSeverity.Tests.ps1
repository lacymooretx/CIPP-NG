# Aspendora fork: alert failures caused by a missing licence are logged at Info so the logbook
# notification rule (Alert/Error) doesn't email every run (IMTEC Defender pending remediation, 2026-11-01).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Alerts/Get-CIPPAlertFailureSeverity.ps1')
}

Describe 'Get-CIPPAlertFailureSeverity' {
    It 'treats <Text> as a missing licence (Info)' -ForEach @(
        @{ Text = 'The account is not provisioned. You do not the correct M365 license to access this information..' }
        @{ Text = 'Unauthorized request - Account is not provisioned.' }
        @{ Text = 'AadPremiumLicenseRequired: Tenant must have Azure AD Premium' }
        @{ Text = 'Tenant does not have a premium license' }
        @{ Text = 'This feature requires Entra ID P2' }
        @{ Text = 'The tenant does not have the required license for this operation' }
    ) {
        Get-CIPPAlertFailureSeverity -ErrorText $Text | Should -Be 'Info'
    }

    It 'keeps real failures at Error: <Text>' -ForEach @(
        @{ Text = 'Request Authorization failed' }
        @{ Text = 'Access is denied to the requested resource.' }
        @{ Text = 'Too many requests (429)' }
        @{ Text = "The term 'Add-CIPPBPAField' is not recognized" }
        @{ Text = '' }
    ) {
        Get-CIPPAlertFailureSeverity -ErrorText $Text | Should -Be 'Error'
    }

    It 'accepts null' {
        Get-CIPPAlertFailureSeverity -ErrorText $null | Should -Be 'Error'
    }
}
