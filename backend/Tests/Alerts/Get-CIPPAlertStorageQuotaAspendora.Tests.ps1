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
    function New-ExoRequest {
        param($tenantid, $cmdlet, $cmdParams)
        if ($script:ExoThrows) { throw 'exchange unavailable' }
        $script:ExoCalls.Add($cmdParams.Identity)
        $script:LiveStats[$cmdParams.Identity]
    }
    function Get-ExoOnlineStringBytes { param($SizeString) [long]$SizeString }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) $script:Logged.Add($message) }
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
        $script:ExoThrows = $false
        $script:LiveStats = @{}
        $script:ExoCalls = [System.Collections.Generic.List[string]]::new()
        $script:Logged = [System.Collections.Generic.List[string]]::new()
    }

    Context 'live confirmation' {
        It 'drops a mailbox the live figure shows is under the threshold, and resolves it' {
            # The real false alert: the report still said 94% after the mailbox was cleaned up.
            $script:Mailboxes = @(New-Mailbox 'ken@contoso.com' 94)
            $script:LiveStats['ken@contoso.com'] = [pscustomobject]@{ TotalItemSize = [long](32GB); TotalDeletedItemSize = [long](1GB) }

            Invoke-Alert | Should -BeNullOrEmpty
            (Get-QuotaState) | Where-Object { $_.Status -eq 'Open' } | Should -BeNullOrEmpty
        }

        It 'does not record a false finding as notified, so a real one later still alerts' {
            $script:Mailboxes = @(New-Mailbox 'ken@contoso.com' 94)
            $script:LiveStats['ken@contoso.com'] = [pscustomobject]@{ TotalItemSize = [long](32GB) }
            $null = Invoke-Alert

            $script:LiveStats['ken@contoso.com'] = [pscustomobject]@{ TotalItemSize = [long](94GB) }
            $Second = Invoke-Alert
            $Second | Should -HaveCount 1
            $Second[0].Notified | Should -Be 'new'
        }

        It 'reports the live figure, counting deleted items' {
            $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 86)
            $script:LiveStats['amber@contoso.com'] = [pscustomobject]@{ TotalItemSize = [long](90GB); TotalDeletedItemSize = [long](6GB) }

            $Alert = Invoke-Alert
            $Alert[0].PercentUsed | Should -Be 96
            $Alert[0].Message | Should -BeLike '*96% full*'
        }

        It 'moves to the band the live figure lands in' {
            $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 86)
            $script:LiveStats['amber@contoso.com'] = [pscustomobject]@{ TotalItemSize = [long](96GB) }
            $null = Invoke-Alert

            # Held at the 95 band: the same live figure on the next run must stay quiet.
            Invoke-Alert | Should -BeNullOrEmpty
        }

        It 'still notifies from the report when the live read fails, and says so' {
            $script:ExoThrows = $true
            $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 91)

            $Alert = Invoke-Alert
            $Alert | Should -HaveCount 1
            $Alert[0].PercentUsed | Should -Be 91
            ($script:Logged -join ' ') | Should -BeLike '*could not confirm amber@contoso.com*'
        }

        It 'still notifies from the report when Exchange returns nothing' {
            $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 91)

            Invoke-Alert | Should -HaveCount 1
        }

        It 'makes no Exchange call for a mailbox that is being held' {
            $script:Mailboxes = @(New-Mailbox 'amber@contoso.com' 91)
            $script:LiveStats['amber@contoso.com'] = [pscustomobject]@{ TotalItemSize = [long](91GB) }
            $null = Invoke-Alert
            $script:ExoCalls.Clear()

            $null = Invoke-Alert
            $script:ExoCalls | Should -HaveCount 0
        }
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
