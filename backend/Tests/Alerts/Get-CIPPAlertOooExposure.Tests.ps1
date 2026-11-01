# Aspendora fork (Vikunja CIPP-40): OooExposure scripted alert. Get-CIPPOooExposure is stubbed; Write-AlertTrace is
# stubbed to capture what the alert hands the lifecycle (rows, per-period Id, never the message body).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertOooExposure.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/GraphHelper/Get-AlertContentHash.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Alerts/Get-CIPPAlertFailureSeverity.ps1')

    function Get-CIPPOooExposure { [CmdletBinding()] param($TenantFilter) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) }
    function Write-AlertTrace {
        param($cmdletName, $tenantFilter, $data, [switch]$Append)
        $script:Traced = @($data)
        $script:Appended = [bool]$Append
        $script:TraceCalls++
    }

    function script:New-Row {
        param($Mailbox, $Severity, $State = 'Scheduled', $Window = 'Active', $Start = '2026-11-03T14:00:00Z', $End = '2026-11-10T14:00:00Z', $Snippet = 'Away. Ask [email] or call [phone].', $Reasons = 'names colleague address(es) bob@contoso.com; contains 1 phone number(s)')
        [pscustomobject]@{
            Mailbox = $Mailbox; DisplayName = "User $Mailbox"; Severity = $Severity; AutoReplyState = $State; ExternalAudience = if ($Severity -eq 'Low') { 'Known' } else { 'All' }
            Window = $Window; StartTime = if ($State -eq 'Scheduled') { $Start }; EndTime = if ($State -eq 'Scheduled') { $End }
            StartCentral = '2026-11-03 08:00 CST (14:00 UTC)'; EndCentral = '2026-11-10 08:00 CST (14:00 UTC)'
            FlagsText = 'InternalEmail, Phone'; Reasons = $Reasons; Snippet = $Snippet
            ExternalMessageText = 'SYNTHETIC-FULL-BODY call 555-123-4567'
        }
    }
    function script:New-Report {
        param($Rows, $Status = 'OK', $Checked = 4, $Read = 4)
        [pscustomobject]@{ Status = $Status; MailboxesChecked = $Checked; SettingsRead = $Read; Rows = @($Rows); Errors = @() }
    }
}

Describe 'Get-CIPPAlertOooExposure' {
    BeforeEach {
        $script:Traced = $null; $script:Appended = $null; $script:TraceCalls = 0
        Mock Write-LogMessage {}
        Mock Get-CIPPOooExposure {
            New-Report @(
                (New-Row 'amy@contoso.com' 'High')
                (New-Row 'bob@contoso.com' 'Medium' -State 'Enabled' -Reasons '')
                (New-Row 'dan@contoso.com' 'Low' -State 'Enabled')
                (New-Row 'gina@contoso.com' 'High' -Window 'Upcoming')
            )
        }
    }

    It 'raises only active High rows by default, in state mode, with a per-period Id' {
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' | Out-Null
        $script:Appended | Should -BeFalse
        $script:Traced.Id | Should -Be @('OooExposure|amy@contoso.com|2026-11-03T14:00:00Z|2026-11-10T14:00:00Z')
    }

    It 'never carries the message body or a UserPrincipalName key' {
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' | Out-Null
        $Item = $script:Traced[0]
        $Item.PSObject.Properties.Name | Should -Not -Contain 'UserPrincipalName'
        $Item.PSObject.Properties.Name | Should -Not -Contain 'ExternalMessageText'
        ($Item | ConvertTo-Json -Compress) | Should -Not -Match 'SYNTHETIC-FULL-BODY|4567'
        $Item.Message | Should -Match 'names colleague address\(es\) bob@contoso.com'
        $Item.Snippet | Should -Be 'Away. Ask [email] or call [phone].'
    }

    It 'adds Medium rows with the switch, keyed "enabled" when there is no schedule' {
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' -InputValue @{ OooExposureIncludeMedium = $true } | Out-Null
        @($script:Traced.Id) | Should -Be @('OooExposure|amy@contoso.com|2026-11-03T14:00:00Z|2026-11-10T14:00:00Z', 'OooExposure|bob@contoso.com|enabled')
        ($script:Traced | Where-Object Mailbox -EQ 'bob@contoso.com').Message | Should -Match 'no contact or payment cues'
    }

    It 'accepts the switch as a string from the alert form' {
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' -InputValue @{ OooExposureIncludeMedium = 'true' } | Out-Null
        @($script:Traced).Count | Should -Be 2
    }

    It 'never raises Known-audience (Low) rows' {
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' -InputValue @{ OooExposureIncludeMedium = $true } | Out-Null
        $script:Traced.Mailbox | Should -Not -Contain 'dan@contoso.com'
    }

    It 'hashes the same while the snippet changes and differently for a new period' {
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' | Out-Null
        $A = (Get-AlertContentHash -AlertItem $script:Traced[0]).ContentHash
        Mock Get-CIPPOooExposure { New-Report @(New-Row 'amy@contoso.com' 'High' -Snippet 'Edited text') }
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' | Out-Null
        (Get-AlertContentHash -AlertItem $script:Traced[0]).ContentHash | Should -Be $A
        Mock Get-CIPPOooExposure { New-Report @(New-Row 'amy@contoso.com' 'High' -Start '2026-12-20T14:00:00Z' -End '2026-12-28T14:00:00Z') }
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' | Out-Null
        (Get-AlertContentHash -AlertItem $script:Traced[0]).ContentHash | Should -Not -Be $A
    }

    It 'reconciles to empty when nothing is exposed' {
        Mock Get-CIPPOooExposure { New-Report @() }
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' | Out-Null
        $script:TraceCalls | Should -Be 1
        @($script:Traced).Count | Should -Be 0
    }

    It 'skips tenants without Exchange Online silently' {
        Mock Get-CIPPOooExposure { New-Report @() -Status 'NoExchange' -Checked 0 -Read 0 }
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' | Out-Null
        $script:TraceCalls | Should -Be 0
        Should -Invoke Write-LogMessage -Times 0 -Exactly
    }

    It 'does not reconcile when no auto-reply settings could be read' {
        Mock Get-CIPPOooExposure { New-Report @() -Checked 5 -Read 0 }
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' | Out-Null
        $script:TraceCalls | Should -Be 0
        Should -Invoke Write-LogMessage -Times 1 -Exactly -ParameterFilter { $sev -eq 'Warning' }
    }

    It 'logs a failure at Error and does not reconcile' {
        Mock Get-CIPPOooExposure { throw 'Could not list mailboxes: Unauthorized' }
        Get-CIPPAlertOooExposure -TenantFilter 'contoso.com' | Out-Null
        $script:TraceCalls | Should -Be 0
        Should -Invoke Write-LogMessage -Times 1 -Exactly -ParameterFilter { $sev -eq 'Error' }
    }
}
