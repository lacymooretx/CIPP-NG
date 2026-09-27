# Storage quota alert on CIPP 11.0's AlertLifecycle.
#
# Notification decisions stay with the fork's banded logic (Select-CIPPStorageAlertToNotify: new,
# worsened across 85/90/95, or a reminder after the re-notify window) because the lifecycle cannot
# express bands or reminders. What the lifecycle adds, and what is asserted here, is:
#   - an honest state: the full at-risk set is reconciled silently every run, so a mailbox that is
#     still near quota shows Open and one that recovered shows Resolved;
#   - snoozes set in the alert-management UI suppress this alert's notifications;
#   - the reconcile never leaks into the notification output.
# The real Get-CIPPMailboxQuotaRisk and Select-CIPPStorageAlertToNotify run here.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Tests/Alerts/AlertLifecycleHarness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Storage/Get-CIPPMailboxQuotaRisk.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Storage/Select-CIPPStorageAlertToNotify.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertStorageQuota.ps1')

    function Test-CIPPTenantManaged { param($TenantFilter) [pscustomobject]@{ IsManaged = $script:Managed } }
    function New-GraphGetRequest {
        param($tenantid, $AsApp, $uri)
        if ($script:GraphThrows) { throw 'report unavailable' }
        $script:Mailboxes
    }
    function New-Mailbox {
        param($Upn, [double]$Percent)
        $Hard = 100GB
        [pscustomobject]@{
            userPrincipalName                = $Upn
            storageUsedInBytes               = [long]($Hard * $Percent / 100)
            issueWarningQuotaInBytes         = [long](90GB)
            prohibitSendReceiveQuotaInBytes  = [long]$Hard
            recipientType                    = 'User'
            hasArchive                       = $false
        }
    }
    function Invoke-Alert { @(Get-CIPPAlertStorageQuota -TenantFilter 'contoso.com') }
    function Get-QuotaState { Get-LifecycleState 'Get-CIPPAlertStorageQuota' }
}

Describe 'Get-CIPPAlertStorageQuota' {
    BeforeEach {
        Reset-AlertStore
        $script:Managed = $true
        $script:GraphThrows = $false
        $script:Mailboxes = @()
    }

    It 'notifies a new at-risk mailbox once, then holds it' {
        $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 91)

        $First = Invoke-Alert
        $First | Should -HaveCount 1
        $First[0].UserPrincipalName | Should -Be 'amber@contoso.com'
        $First[0].Notified | Should -Be 'new'
        Invoke-Alert | Should -BeNullOrEmpty
    }

    It 'notifies again when the mailbox crosses into a higher band' {
        $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 91)
        $null = Invoke-Alert
        $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 96)

        (Invoke-Alert)[0].Notified | Should -Be 'worsened'
    }

    It 'keeps the lifecycle honest: Open while at risk, Resolved once it recovers' {
        $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 91)
        $null = Invoke-Alert
        $null = Invoke-Alert
        (Get-QuotaState)['amber@contoso.com'] | Should -Be 'Open'

        $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 40)
        $null = Invoke-Alert
        (Get-QuotaState)['amber@contoso.com'] | Should -Be 'Resolved'
    }

    It 'does not emit reconcile output as notifications' {
        # The reconcile returns New items; if that leaked, a held mailbox would re-notify.
        $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 91)
        $null = Invoke-Alert
        $script:Store['AlertLifecycle'] = @{}

        Invoke-Alert | Should -BeNullOrEmpty
    }

    It 'honours a snooze set in the alert-management UI' {
        $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 91), (New-Mailbox 'blair@contoso.com' 92)
        $AmberHash = (Get-AlertContentHash -AlertItem @{ UserPrincipalName = 'amber@contoso.com' }).ContentHash
        $script:Snoozes = @{ $AmberHash = [pscustomobject]@{ RowKey = 's1'; SnoozeUntil = '2099-01-01' } }

        $Alerted = Invoke-Alert
        $Alerted | Should -HaveCount 1
        $Alerted[0].UserPrincipalName | Should -Be 'blair@contoso.com'
    }

    It 'resolves open items when the tenant goes out of scope' {
        $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 91)
        $null = Invoke-Alert
        $script:Managed = $false

        Invoke-Alert | Should -BeNullOrEmpty
        (Get-QuotaState)['amber@contoso.com'] | Should -Be 'Resolved'
    }

    It 'does not reconcile when the usage report cannot be read' {
        $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 91)
        $null = Invoke-Alert
        $script:GraphThrows = $true

        Invoke-Alert | Should -BeNullOrEmpty
        (Get-QuotaState)['amber@contoso.com'] | Should -Be 'Open'
    }
}
