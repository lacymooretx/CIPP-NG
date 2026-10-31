# Aspendora fork (Vikunja CIPP-8): device-code sign-in report, read one day at a time.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function New-GraphGetRequest {
        param($uri, $tenantid, $ErrorAction)
        $script:Uris.Add([uri]::UnescapeDataString($uri))
        $script:Calls++
        if ($script:Mode -eq 'nop1') { throw 'Authentication_RequestFromNonPremiumTenantOrB2CTenant' }
        if ($script:Mode -eq 'timeout' -and $script:Calls -eq 2) { throw 'The request timed out after 100s.' }
        if ($script:Calls -eq 1) { return $script:Day1 }
        if ($script:Calls -eq 2) { return $script:Day2 }
        return @()
    }
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Identity/Get-CIPPDeviceCodeSignIns.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Identity/Reports/Invoke-ListDeviceCodeSignIns.ps1')
    $script:Now = [datetime]::new(2026, 10, 31, 18, 0, 0, [DateTimeKind]::Utc)
    function SignIn {
        param($Id, $Upn, $App = 'Microsoft Azure CLI', $AppId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46', $When, $Code = 0, $Ip = '1.2.3.4', $DeviceId = 'dev1')
        [pscustomobject]@{ id = $Id; createdDateTime = $When; userPrincipalName = $Upn; appDisplayName = $App; appId = $AppId; ipAddress = $Ip
            location = @{ city = 'Houston'; countryOrRegion = 'US' }; status = @{ errorCode = $Code }
            deviceDetail = @{ deviceId = $DeviceId; displayName = 'LAPTOP-1'; operatingSystem = 'Windows'; browser = '' } }
    }
}

Describe 'Get-CIPPDeviceCodeSignIns' {
    BeforeEach {
        $script:Uris = [System.Collections.Generic.List[string]]::new()
        $script:Calls = 0
        $script:Mode = 'ok'
        $script:Day1 = @(); $script:Day2 = @()
    }

    It 'queries one bounded day per call, newest first, and caps Days at 30' {
        $R = Get-CIPPDeviceCodeSignIns -TenantFilter 'contoso.com' -Days 45 -Now $script:Now
        $R.Days | Should -Be 30
        $script:Calls | Should -Be 30
        $script:Uris[0] | Should -Match "createdDateTime ge 2026-10-30T18:00:00Z and createdDateTime lt 2026-10-31T18:00:00Z and authenticationProtocol eq 'deviceCode'"
        $script:Uris[0] | Should -Match '^https://graph.microsoft.com/beta/auditLogs/signIns'
        $script:Uris[29] | Should -Match 'createdDateTime ge 2026-10-01T18:00:00Z'
        $R.TotalSignIns | Should -Be 0
        $R.Message | Should -Match 'No device-code sign-ins'
    }

    It 'summarises per user, app and device with success and failure counts' {
        $script:Day1 = @(
            (SignIn 's1' 'Admin@contoso.com' -When '2026-10-31T15:00:00Z')
            (SignIn 's2' 'admin@contoso.com' -When '2026-10-31T16:00:00Z' -Code 50126 -Ip '5.6.7.8')
            (SignIn 's3' 'room@contoso.com' -App 'Microsoft Teams Rooms' -AppId 'room-app' -When '2026-10-31T10:00:00Z' -DeviceId 'mtr1')
        )
        $script:Day2 = @(
            (SignIn 's4' 'admin@contoso.com' -When '2026-10-30T12:00:00Z')
            (SignIn 's1' 'Admin@contoso.com' -When '2026-10-31T15:00:00Z')
        )
        $R = Get-CIPPDeviceCodeSignIns -TenantFilter 'contoso.com' -Days 2 -Now $script:Now
        $R.TotalSignIns | Should -Be 4
        $R.Summary.Count | Should -Be 2
        $Admin = $R.Summary | Where-Object { $_.UserPrincipalName -eq 'admin@contoso.com' }
        $Admin.Count | Should -Be 3
        $Admin.SuccessCount | Should -Be 2
        $Admin.FailureCount | Should -Be 1
        $Admin.IPAddresses | Should -Be '1.2.3.4, 5.6.7.8'
        $Admin.Locations | Should -Be 'Houston, US'
        $Admin.LastSeen | Should -Be '2026-10-31 11:00 CDT (16:00 UTC)'
        $Admin.FirstSeen | Should -Match '2026-10-30 07:00 CDT'
        $R.Summary[0].UserPrincipalName | Should -Be 'admin@contoso.com'
        $R.Message | Should -Match '4 device-code sign-in'
    }

    It 'returns a clear unlicensed result without P1 and stops querying' {
        $script:Mode = 'nop1'
        $R = Get-CIPPDeviceCodeSignIns -TenantFilter 'contoso.com' -Now $script:Now
        $R.Licensed | Should -BeFalse
        $R.Message | Should -Match 'Entra ID P1'
        $R.Summary | Should -BeNullOrEmpty
        $script:Calls | Should -Be 1
    }

    It 'keeps going past a day that times out and marks the result partial' {
        $script:Mode = 'timeout'
        $script:Day1 = @(SignIn 's1' 'admin@contoso.com' -When '2026-10-31T15:00:00Z')
        $R = Get-CIPPDeviceCodeSignIns -TenantFilter 'contoso.com' -Days 3 -Now $script:Now
        $script:Calls | Should -Be 3
        $R.DaysFailed | Should -Be 1
        $R.DaysQueried | Should -Be 2
        $R.Errors[0] | Should -Match 'timed out'
        $R.Message | Should -Match 'could not be read'
        $R.TotalSignIns | Should -Be 1
    }
}

Describe 'Invoke-ListDeviceCodeSignIns' {
    BeforeEach {
        $script:Uris = [System.Collections.Generic.List[string]]::new()
        $script:Calls = 0; $script:Mode = 'ok'; $script:Day1 = @(); $script:Day2 = @()
    }

    It 'rejects AllTenants and bad Days' {
        (Invoke-ListDeviceCodeSignIns -Request @{ Query = @{ tenantFilter = 'AllTenants' } }).StatusCode | Should -Be 400
        (Invoke-ListDeviceCodeSignIns -Request @{ Query = @{ tenantFilter = 'contoso.com'; Days = 'abc' } }).StatusCode | Should -Be 400
        (Invoke-ListDeviceCodeSignIns -Request @{ Query = @{ tenantFilter = 'contoso.com'; Days = '0' } }).StatusCode | Should -Be 400
    }

    It 'defaults to 30 days and clamps larger values' {
        $R = Invoke-ListDeviceCodeSignIns -Request @{ Query = @{ tenantFilter = 'contoso.com' } }
        $R.StatusCode | Should -Be 200
        $R.Body.Days | Should -Be 30
        (Invoke-ListDeviceCodeSignIns -Request @{ Query = @{ tenantFilter = 'contoso.com'; Days = '90' } }).Body.Days | Should -Be 30
        (Invoke-ListDeviceCodeSignIns -Request @{ Query = @{ tenantFilter = 'contoso.com'; Days = '7' } }).Body.Days | Should -Be 7
    }
}
