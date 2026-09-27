# The alert reports applications users were blocked from for want of admin consent.
#
# The two guards under test are the ones that were learned the hard way: the ControlR CIPP ingest
# fix replayed an entire never-ingested history in one cycle and opened 50 ConnectWise tickets
# (#57308-#57357). A first run here sweeps retained sign-in history across every tenant at once, so
# it must establish a baseline silently, and a burst past that baseline must be capped - with the
# suppressed items recorded so they cannot arrive later as a second flood.
#
# Dedup runs on the REAL AlertLifecycle in -Append mode (see AlertLifecycleHarness.ps1), so these
# tests assert on what is notified across consecutive runs.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Tests/Alerts/AlertLifecycleHarness.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertAppConsentBlocked.ps1')

    function New-GraphGetRequest {
        param($uri, $tenantid, $noPagination, $ErrorAction)
        if ($script:GraphThrows) { throw 'Graph exploded' }
        $script:LastUri = $uri
        return $script:SignIns
    }
    function Get-Tenants { param($TenantFilter) [pscustomobject]@{ customerId = 'cust-guid-0001' } }

    function New-SignIn {
        param($AppId, $AppName = 'TestApp', $Upn = 'user@contoso.com', $ErrorCode = 90094, $When = $null)
        if (-not $When) { $When = (Get-Date).ToUniversalTime().AddHours(-1) }
        [pscustomobject]@{
            createdDateTime     = $When
            userPrincipalName   = $Upn
            appDisplayName      = $AppName
            appId               = $AppId
            resourceDisplayName = 'Microsoft Graph'
            status              = [pscustomobject]@{ errorCode = $ErrorCode }
        }
    }
    function Invoke-Alert { param($InputValue) @(Get-CIPPAlertAppConsentBlocked -TenantFilter 'contoso.com' -InputValue $InputValue) }
    function Set-Migrated { Set-OldBaseline -Partition 'AppConsentBlockedDelta' -Tenant 'contoso.com' -Ids @(); $null = Invoke-Alert }
}

Describe 'Get-CIPPAlertAppConsentBlocked' {
    BeforeEach {
        Reset-AlertStore
        $script:SignIns = @()
        $script:LastUri = $null
        $script:GraphThrows = $false
    }

    Context 'first run and hand-over' {
        It 'surfaces nothing on the first run of a never-baselined tenant' {
            $script:SignIns = @(New-SignIn -AppId 'app-1'), (New-SignIn -AppId 'app-2')

            Invoke-Alert | Should -BeNullOrEmpty
            (Get-LifecycleState 'Get-CIPPAlertAppConsentBlocked').Keys | Should -HaveCount 2
        }

        It 'does not re-ticket apps the old baseline knew, even ones not blocked this window' {
            Set-OldBaseline -Partition 'AppConsentBlockedDelta' -Tenant 'contoso.com' -Ids @('app-old', 'app-older')
            $script:SignIns = @(New-SignIn -AppId 'app-old'), (New-SignIn -AppId 'app-new')

            $Alerted = Invoke-Alert
            $Alerted | Should -HaveCount 1
            $Alerted[0].'Application Id' | Should -Be 'app-new'

            # app-older was not in this window; it must still be known when it next appears.
            $script:SignIns = @(New-SignIn -AppId 'app-older')
            Invoke-Alert | Should -BeNullOrEmpty
        }

        It 'does not swallow the first finding on a tenant that has only ever been quiet' {
            $null = Invoke-Alert
            $script:SignIns = @(New-SignIn -AppId 'app-1')
            Invoke-Alert | Should -HaveCount 1
        }
    }

    Context 'across runs' {
        BeforeEach { Set-Migrated }

        It 'alerts once per application and not again while it keeps being blocked' {
            $script:SignIns = @(New-SignIn -AppId 'app-1')
            Invoke-Alert | Should -HaveCount 1
            Invoke-Alert | Should -BeNullOrEmpty
        }

        It 'keeps an app open through quiet windows (event stream, not state)' {
            $script:SignIns = @(New-SignIn -AppId 'app-1')
            $null = Invoke-Alert
            $script:SignIns = @()
            $null = Invoke-Alert

            (Get-LifecycleState 'Get-CIPPAlertAppConsentBlocked')['app-1'] | Should -Be 'Open'
            $script:SignIns = @(New-SignIn -AppId 'app-1')
            Invoke-Alert | Should -BeNullOrEmpty
        }

        It 'treats a block after 30 quiet days as a new episode' {
            $script:SignIns = @(New-SignIn -AppId 'app-1')
            $null = Invoke-Alert
            foreach ($Row in $script:Store['AlertLifecycle'].Values) { $Row.LastSeen = [datetime]::UtcNow.AddDays(-31).ToString('o') }
            $script:SignIns = @()
            $null = Invoke-Alert
            (Get-LifecycleState 'Get-CIPPAlertAppConsentBlocked')['app-1'] | Should -Be 'Resolved'

            $script:SignIns = @(New-SignIn -AppId 'app-1')
            Invoke-Alert | Should -HaveCount 1
        }
    }

    Context 'ticket content' {
        BeforeEach { Set-Migrated }

        It 'groups many blocked users into one alert per application' {
            $script:SignIns = @(
                New-SignIn -AppId 'app-new' -Upn 'amber@contoso.com'
                New-SignIn -AppId 'app-new' -Upn 'blair@contoso.com'
                New-SignIn -AppId 'app-new' -Upn 'danny@contoso.com'
            )

            $Alerted = Invoke-Alert
            $Alerted | Should -HaveCount 1
            $Alerted[0].'Users Blocked' | Should -Be 3
            $Alerted[0].'Attempts' | Should -Be 3
        }

        It 'carries a ready-to-use admin consent URL' {
            $script:SignIns = @(New-SignIn -AppId 'abc-123')

            (Invoke-Alert)[0].'Admin Consent URL' |
                Should -Be 'https://login.microsoftonline.com/cust-guid-0001/adminconsent?client_id=abc-123'
        }

        It 'reports both consent error codes' {
            $script:SignIns = @(New-SignIn -AppId 'a' -ErrorCode 65001), (New-SignIn -AppId 'a' -ErrorCode 90094)

            (Invoke-Alert)[0].'Error Codes' | Should -Be '65001, 90094'
        }
    }

    Context 'burst protection' {
        It 'caps what it surfaces, keeps the rest open so they never arrive later, and warns' {
            Set-Migrated
            $script:SignIns = 1..25 | ForEach-Object { New-SignIn -AppId "app-$_" }
            $Cap = [pscustomobject]@{ AppConsentBlockedMaxPerCycle = 10 }

            Invoke-Alert -InputValue $Cap | Should -HaveCount 10
            ($script:Logs | Where-Object { $_.Sev -eq 'Warning' }).Message | Should -Match 'exceeded the per-cycle cap'
            Invoke-Alert -InputValue $Cap | Should -BeNullOrEmpty
        }
    }

    Context 'query and failure paths' {
        It 'sweeps only the configured lookback window' {
            $script:SignIns = @(New-SignIn -AppId 'a')

            $null = Invoke-Alert -InputValue ([pscustomobject]@{ AppConsentBlockedLookbackHours = 6 })

            $Expected = (Get-Date).ToUniversalTime().AddHours(-6).ToString('yyyy-MM-ddTHH')
            $script:LastUri | Should -Match ([regex]::Escape($Expected))
            $script:LastUri | Should -Match 'errorCode eq 65001'
            $script:LastUri | Should -Match 'errorCode eq 90094'
        }

        It 'logs an error instead of throwing when the sign-in query fails' {
            $script:GraphThrows = $true

            { Invoke-Alert } | Should -Not -Throw
            ($script:Logs | Where-Object { $_.Sev -eq 'Error' }).Message | Should -Match 'Could not check for blocked app consent'
        }
    }
}
