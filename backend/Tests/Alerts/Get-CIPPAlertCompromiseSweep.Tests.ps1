BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Get-CIPPCompromiseSweepSuccess.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertCompromiseSweep.ps1')

    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) $script:Logs.Add("[$sev] $message") }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data, [switch]$Append) $data }
    function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = $Exception.Exception.Message } }
    function Get-CIPPIPAllowBlockList { param($TenantFilter) $script:Trusted | ForEach-Object { [pscustomobject]@{ Ip = $_ } } }
    function Resolve-CIPPIPAllowBlockList { param($IPAddress, $Entries) @{ State = $(if ($script:Trusted -contains $IPAddress) { 'Trusted' } else { 'None' }) } }

    function New-SignIn { param($Upn, $Ip, [int]$Code = 50126, $App = 'Office', $When = (Get-Date).ToUniversalTime().AddHours(-1))
        [pscustomobject]@{ createdDateTime = $When.ToString('o'); userPrincipalName = $Upn; userId = "id-$Upn"; ipAddress = $Ip; appDisplayName = $App; appId = "app-$App"
            status = [pscustomobject]@{ errorCode = $Code }; location = [pscustomobject]@{ city = 'X'; countryOrRegion = 'GB' } }
    }

    # Graph is answered from these script-scoped fixtures by URL shape.
    function New-GraphGetRequest {
        param($uri, $tenantid, $noPagination, $ErrorAction)
        $u = [uri]::UnescapeDataString($uri)
        if ($u -match "authenticationProtocol eq 'deviceCode'") { if ($script:NoP1) { throw 'Authentication_RequestFromNonPremiumTenantOrB2CTenant' }; return $script:DeviceCode }
        if ($u -match 'errorCode eq 50126') { return $script:Failures }
        if ($u -match 'directoryAudits') { return $script:Registrations }
        if ($u -match '/users/') { return $script:Users[($u -split '/users/')[1].Split('?')[0]] }
        if ($u -match "userId eq '([^']+)'") { return @($script:PriorSignIns[$Matches[1]] | Where-Object { $_ }) }
        if ($u -match 'status/errorCode eq 0') {
            $Before = $u -match 'createdDateTime lt'
            if ($u -match "userPrincipalName eq '([^']+)'") { $Upn = $Matches[1]; return $(if ($Before) { $script:Baseline[$Upn] } else { $script:Successes | Where-Object { $_.userPrincipalName -eq $Upn } }) }
            if ($u -match "ipAddress eq '([^']+)'") { $Ip = $Matches[1]; return $script:Successes | Where-Object { $_.ipAddress -eq $Ip } }
        }
        @()
    }
}

Describe 'Get-CIPPAlertCompromiseSweep' {
    BeforeEach {
        $script:Logs = [System.Collections.Generic.List[string]]::new()
        $script:NoP1 = $false
        $script:Trusted = @()
        $script:DeviceCode = @(); $script:Failures = @(); $script:Registrations = @(); $script:Successes = @()
        $script:Users = @{}; $script:PriorSignIns = @{}; $script:Baseline = @{}
    }

    Context 'Device code' {
        It 'raises High for a successful device-code sign-in, ignores failures and allow-listed accounts' {
            $script:DeviceCode = @(
                (New-SignIn 'victim@t.com' '1.1.1.1' 0 'Graph')
                (New-SignIn 'victim@t.com' '1.1.1.1' 50199 'Graph')
                (New-SignIn 'room@t.com' '2.2.2.2' 0 'Teams')
            )
            $R = @(Get-CIPPAlertCompromiseSweep -TenantFilter 't' -InputValue ([pscustomobject]@{ CompromiseSweepDeviceCodeAllowList = 'ROOM@t.com' }))
            $R.Count | Should -Be 1
            $R[0].Detection | Should -Be 'Device-code sign-in'
            $R[0].Severity | Should -Be 'High'
            $R[0].Account | Should -Be 'victim@t.com'
            $R[0].Id | Should -Be 'DeviceCode|victim@t.com|app-Graph'
        }
    }

    Context 'Password spray' {
        BeforeEach { $script:Failures = @(1..5 | ForEach-Object { New-SignIn "u$_@t.com" '9.9.9.9' }) }

        It 'raises Medium when one IP fails against the threshold number of accounts with no success' {
            $R = @(Get-CIPPAlertCompromiseSweep -TenantFilter 't')
            $R.Detection | Should -Be 'Password spray'
            $R.Severity | Should -Be 'Medium'
            $R.Id | Should -Be 'Spray|9.9.9.9'
        }

        It 'escalates to High when the spraying IP also signs someone in' {
            $script:Successes = @(New-SignIn 'u3@t.com' '9.9.9.9' 0)
            (@(Get-CIPPAlertCompromiseSweep -TenantFilter 't')).Severity | Should -Be 'High'
        }

        It 'ignores shared egress where three or more different users sign in successfully' {
            $script:Successes = @(1..3 | ForEach-Object { New-SignIn "u$_@t.com" '9.9.9.9' 0 })
            @(Get-CIPPAlertCompromiseSweep -TenantFilter 't').Count | Should -Be 0
        }

        It 'ignores IPs on the CIPP trusted list' {
            $script:Trusted = @('9.9.9.9')
            @(Get-CIPPAlertCompromiseSweep -TenantFilter 't').Count | Should -Be 0
        }
    }

    Context 'Distributed brute force' {
        BeforeEach { $script:Failures = @('a', 'b', 'c', 'home' | ForEach-Object { New-SignIn 'bryan@t.com' "ip-$_" }) }

        It 'raises Medium for failures from enough IPs the user does not normally use' {
            $R = @(Get-CIPPAlertCompromiseSweep -TenantFilter 't')
            $R.Detection | Should -Be 'Distributed brute force'
            $R.Severity | Should -Be 'Medium'
            $R.IPs | Should -Match 'ip-a'
        }

        It "does not count the user's own normal IPs, so typos at home do not reach the threshold" {
            $script:Baseline['bryan@t.com'] = @((New-SignIn 'bryan@t.com' 'ip-home' 0), (New-SignIn 'bryan@t.com' 'ip-c' 0))
            @(Get-CIPPAlertCompromiseSweep -TenantFilter 't').Count | Should -Be 0
        }

        It 'escalates to High on a success from an attacker IP, but not from shared office egress' {
            $script:Successes = @(New-SignIn 'bryan@t.com' 'ip-a' 0)
            (@(Get-CIPPAlertCompromiseSweep -TenantFilter 't')).Severity | Should -Be 'High'
            $script:Successes = @((New-SignIn 'bryan@t.com' 'ip-a' 0), (New-SignIn 'x@t.com' 'ip-a' 0), (New-SignIn 'y@t.com' 'ip-a' 0))
            (@(Get-CIPPAlertCompromiseSweep -TenantFilter 't')).Severity | Should -Be 'Medium'
        }

        It 'surfaces only High detections when the minimum severity is High' {
            @(Get-CIPPAlertCompromiseSweep -TenantFilter 't' -InputValue ([pscustomobject]@{ CompromiseSweepMinSeverity = 'High' })).Count | Should -Be 0
        }
    }

    Context 'MFA registered on a dormant account' {
        BeforeEach {
            $script:Registrations = @([pscustomobject]@{
                    activityDateTime = (Get-Date).ToUniversalTime().AddHours(-2).ToString('o'); activityDisplayName = 'User registered security info'; result = 'success'
                    targetResources = @([pscustomobject]@{ type = 'User'; id = 'u1'; userPrincipalName = 'old@t.com' })
                    initiatedBy = [pscustomobject]@{ user = [pscustomobject]@{ userPrincipalName = 'old@t.com'; ipAddress = '5.5.5.5' } }
                })
            $script:Users['u1'] = [pscustomobject]@{ id = 'u1'; userPrincipalName = 'old@t.com'; createdDateTime = '2024-01-01T00:00:00Z' }
        }

        It 'raises High when the account had no successful sign-in in the dormant window' {
            $R = @(Get-CIPPAlertCompromiseSweep -TenantFilter 't')
            $R.Detection | Should -Be 'MFA registered on dormant account'
            $R.Severity | Should -Be 'High'
            $R.IPs | Should -Be '5.5.5.5'
        }

        It 'stays quiet for an account that signs in regularly, and for a newly created account' {
            $script:PriorSignIns['u1'] = @(New-SignIn 'old@t.com' '1.1.1.1' 0)
            @(Get-CIPPAlertCompromiseSweep -TenantFilter 't').Count | Should -Be 0
            $script:PriorSignIns['u1'] = @()
            $script:Users['u1'].createdDateTime = (Get-Date).ToUniversalTime().AddDays(-3).ToString('o')
            @(Get-CIPPAlertCompromiseSweep -TenantFilter 't').Count | Should -Be 0
        }
    }

    Context 'Licensing' {
        It 'skips sign-in detections with a warning on a tenant without Entra ID P1' {
            $script:NoP1 = $true
            $script:Failures = @(1..5 | ForEach-Object { New-SignIn "u$_@t.com" '9.9.9.9' })
            @(Get-CIPPAlertCompromiseSweep -TenantFilter 't').Count | Should -Be 0
            ($script:Logs -join "`n") | Should -Match 'device-code check skipped'
        }
    }
}
