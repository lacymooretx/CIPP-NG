# The alert reports applications users were blocked from for want of admin consent.
#
# The two guards under test are the ones that were learned the hard way: the ControlR CIPP ingest
# fix replayed an entire never-ingested history in one cycle and opened 50 ConnectWise tickets
# (#57308-#57357). A first run here sweeps retained sign-in history across every tenant at once, so
# it must establish a baseline silently, and a burst past that baseline must be capped - with the
# suppressed items recorded as seen so they cannot arrive later as a second flood.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertAppConsentBlocked.ps1'

    function New-GraphGetRequest { param($uri, $tenantid, $noPagination, $ErrorAction) $script:LastUri = $uri; return $script:SignIns }
    function Get-Tenants { param($TenantFilter) [pscustomobject]@{ customerId = 'cust-guid-0001' } }
    function Get-CIPPTable { param($Table, $TableName) @{ Context = 'stub' } }
    function Get-CIPPAzDataTableEntity { param($Context, $Filter) return $script:PreviousRow }
    function Add-CIPPAzDataTableEntity { param($Context, $Entity, [switch]$Force) $script:Written = $Entity }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data) $script:Alerted = @($data) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) $script:Logs += @([pscustomobject]@{ Message = $message; Sev = $sev }) }
    function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }

    . $FunctionPath

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
    function Set-Baseline { param([string[]]$AppIds) $script:PreviousRow = [pscustomobject]@{ delta = (ConvertTo-Json -InputObject $AppIds -Compress) } }
}

Describe 'Get-CIPPAlertAppConsentBlocked' {
    BeforeEach {
        $script:SignIns = @()
        $script:PreviousRow = $null
        $script:Written = $null
        $script:Alerted = $null
        $script:Logs = @()
        $script:LastUri = $null
    }

    Context 'first run on a tenant' {
        It 'establishes a baseline and surfaces nothing' {
            $script:SignIns = @(New-SignIn -AppId 'app-1'), (New-SignIn -AppId 'app-2')

            Get-CIPPAlertAppConsentBlocked -TenantFilter 'contoso.com'

            $script:Alerted | Should -BeNullOrEmpty
            ($script:Written.delta | ConvertFrom-Json) | Should -HaveCount 2
            ($script:Logs.Message -join ' ') | Should -Match 'baseline established'
        }
    }

    Context 'with an existing baseline' {
        It 'alerts only on an application never seen blocked before' {
            Set-Baseline -AppIds @('app-known')
            $script:SignIns = @(New-SignIn -AppId 'app-known'), (New-SignIn -AppId 'app-new' -AppName 'Granola')

            Get-CIPPAlertAppConsentBlocked -TenantFilter 'contoso.com'

            $script:Alerted | Should -HaveCount 1
            $script:Alerted[0].'Application' | Should -Be 'Granola'
        }

        It 'does not re-alert on an application already surfaced' {
            Set-Baseline -AppIds @('app-known')
            $script:SignIns = @(New-SignIn -AppId 'app-known')

            Get-CIPPAlertAppConsentBlocked -TenantFilter 'contoso.com'

            $script:Alerted | Should -BeNullOrEmpty
        }

        It 'groups many blocked users into one alert per application' {
            Set-Baseline -AppIds @()
            $script:SignIns = @(
                New-SignIn -AppId 'app-new' -Upn 'amber@contoso.com'
                New-SignIn -AppId 'app-new' -Upn 'blair@contoso.com'
                New-SignIn -AppId 'app-new' -Upn 'danny@contoso.com'
            )

            Get-CIPPAlertAppConsentBlocked -TenantFilter 'contoso.com'

            $script:Alerted | Should -HaveCount 1
            $script:Alerted[0].'Users Blocked' | Should -Be 3
            $script:Alerted[0].'Attempts' | Should -Be 3
        }

        It 'carries a ready-to-use admin consent URL' {
            Set-Baseline -AppIds @()
            $script:SignIns = @(New-SignIn -AppId 'abc-123')

            Get-CIPPAlertAppConsentBlocked -TenantFilter 'contoso.com'

            $script:Alerted[0].'Admin Consent URL' |
                Should -Be 'https://login.microsoftonline.com/cust-guid-0001/adminconsent?client_id=abc-123'
        }

        It 'reports both consent error codes' {
            Set-Baseline -AppIds @()
            $script:SignIns = @(New-SignIn -AppId 'a' -ErrorCode 65001), (New-SignIn -AppId 'a' -ErrorCode 90094)

            Get-CIPPAlertAppConsentBlocked -TenantFilter 'contoso.com'

            $script:Alerted[0].'Error Codes' | Should -Be '65001, 90094'
        }
    }

    Context 'burst protection' {
        It 'caps what it surfaces, records the rest as seen, and warns' {
            Set-Baseline -AppIds @()
            $script:SignIns = 1..25 | ForEach-Object { New-SignIn -AppId "app-$_" }

            Get-CIPPAlertAppConsentBlocked -TenantFilter 'contoso.com' -InputValue ([pscustomobject]@{ AppConsentBlockedMaxPerCycle = 10 })

            $script:Alerted | Should -HaveCount 10
            # Suppressed items must still be recorded, or they arrive later as a second flood.
            ($script:Written.delta | ConvertFrom-Json) | Should -HaveCount 25
            ($script:Logs | Where-Object { $_.Sev -eq 'Warning' }).Message | Should -Match 'exceeded the per-cycle cap'
        }
    }

    Context 'quiet and failure paths' {
        It 'leaves the baseline untouched when nothing was blocked' {
            Set-Baseline -AppIds @('app-known')
            $script:SignIns = @()

            Get-CIPPAlertAppConsentBlocked -TenantFilter 'contoso.com'

            # Clearing here would make every known app new again on the next failure.
            $script:Written | Should -BeNullOrEmpty
            $script:Alerted | Should -BeNullOrEmpty
        }

        It 'sweeps only the configured lookback window' {
            Set-Baseline -AppIds @()
            $script:SignIns = @(New-SignIn -AppId 'a')

            Get-CIPPAlertAppConsentBlocked -TenantFilter 'contoso.com' -InputValue ([pscustomobject]@{ AppConsentBlockedLookbackHours = 6 })

            $Expected = (Get-Date).ToUniversalTime().AddHours(-6).ToString('yyyy-MM-ddTHH')
            $script:LastUri | Should -Match ([regex]::Escape($Expected))
            $script:LastUri | Should -Match 'errorCode eq 65001'
            $script:LastUri | Should -Match 'errorCode eq 90094'
        }

        It 'logs an error instead of throwing when the sign-in query fails' {
            Set-Baseline -AppIds @()
            Mock New-GraphGetRequest { throw 'Graph exploded' }

            { Get-CIPPAlertAppConsentBlocked -TenantFilter 'contoso.com' } | Should -Not -Throw
            ($script:Logs | Where-Object { $_.Sev -eq 'Error' }).Message | Should -Match 'Could not check for blocked app consent'
        }
    }
}
