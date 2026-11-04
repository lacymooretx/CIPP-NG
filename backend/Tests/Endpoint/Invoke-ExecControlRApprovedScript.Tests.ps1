# Tests for the approved ControlR script endpoint. The allow-list and tenant limit are the point, so most cases prove a
# refusal happens before any call to ControlR.
BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext { [int]$StatusCode; [object]$Body }
    function Get-ExtensionAPIKey { param($Extension) }
    . (Join-Path $BackendRoot 'Modules/CippExtensions/Public/ControlR/Invoke-CippControlRIntegrationRequest.ps1')
    function Resolve-CIPPManagedDevice { param($TenantFilter, $DeviceId, $SerialNumber) }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev) }
    . (Join-Path $BackendRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/MEM/Invoke-ExecControlRApprovedScript.ps1')

    $script:Mid = '11111111-1111-1111-1111-111111111111'
    $script:Cid = '22222222-2222-2222-2222-222222222222'
    $script:Rid = '33333333-3333-3333-3333-333333333333'
    function New-Req { param([hashtable]$Body, [hashtable]$Query = @{}, $Method = 'POST') [pscustomobject]@{ Method = $Method; Query = [pscustomobject]$Query; Body = [pscustomobject]$Body; Headers = @{} } }
    $script:RunBody = @{ Action = 'Run'; tenantFilter = 'aspendora.com'; ScriptKey = 'IdentifyCopilotInstall'; DeviceId = $script:Mid }
}

Describe 'Invoke-ExecControlRApprovedScript' {
    BeforeEach {
        Mock Write-LogMessage {}
        Mock Resolve-CIPPManagedDevice { [pscustomobject]@{ Status = 'Found'; HttpStatus = 200; Device = [pscustomobject]@{ ManagedDeviceId = $script:Mid; DeviceName = 'PC-01' } } }
        Mock Invoke-CippControlRIntegrationRequest {
            if ($Path -eq 'resolve') { return [pscustomobject]@{ Status = 200; Data = [pscustomobject]@{ controlRDeviceId = $script:Cid; cippTenantId = 'aspendora.com'; intuneManagedDeviceId = $script:Mid; matchMethod = 'name' } } }
            [pscustomobject]@{ Status = 200; Data = [pscustomobject]@{ runId = $script:Rid; status = 'Pending' } }
        }
    }

    It 'lists only the two approved scripts' {
        $R = Invoke-ExecControlRApprovedScript -Request (New-Req -Body @{ Action = 'List' } -Method 'GET')
        $R.StatusCode | Should -Be 200
        @($R.Body.Results.ScriptKey) | Should -Be @('CountSavedBrowserLogins', 'IdentifyCopilotInstall')
    }

    It 'refuses a script key that is not approved, without calling ControlR' {
        $R = Invoke-ExecControlRApprovedScript -Request (New-Req -Body ($script:RunBody + @{}) | ForEach-Object { $_.Body.ScriptKey = '7d8a6af6-7150-45c6-addd-4a89e4c5793c'; $_ })
        $R.StatusCode | Should -Be 403
        Should -Invoke Invoke-CippControlRIntegrationRequest -Times 0 -Exactly
    }

    It 'refuses a tenant that is not approved, without touching Intune or ControlR' {
        $R = Invoke-ExecControlRApprovedScript -Request (New-Req -Body ($script:RunBody + @{}) | ForEach-Object { $_.Body.tenantFilter = '3endt.com'; $_ })
        $R.StatusCode | Should -Be 403
        Should -Invoke Resolve-CIPPManagedDevice -Times 0 -Exactly
        Should -Invoke Invoke-CippControlRIntegrationRequest -Times 0 -Exactly
    }

    It 'refuses Run over GET' {
        (Invoke-ExecControlRApprovedScript -Request (New-Req -Body $script:RunBody -Method 'GET')).StatusCode | Should -Be 405
        Should -Invoke Invoke-CippControlRIntegrationRequest -Times 0 -Exactly
    }

    It 'passes a device lookup failure through and runs nothing' {
        Mock Resolve-CIPPManagedDevice { [pscustomobject]@{ Status = 'NotFound'; HttpStatus = 404; Message = 'none'; Candidates = @() } }
        (Invoke-ExecControlRApprovedScript -Request (New-Req -Body $script:RunBody)).StatusCode | Should -Be 404
        Should -Invoke Invoke-CippControlRIntegrationRequest -Times 0 -Exactly
    }

    It 'runs nothing when ControlR has no match' {
        Mock Invoke-CippControlRIntegrationRequest { [pscustomobject]@{ Status = 404; Data = $null; Message = 'ControlR returned HTTP 404.' } }
        (Invoke-ExecControlRApprovedScript -Request (New-Req -Body $script:RunBody)).StatusCode | Should -Be 404
        Should -Invoke Invoke-CippControlRIntegrationRequest -Times 1 -Exactly
    }

    It 'runs nothing when the match is for another tenant or Intune device' -TestCases @(
        @{ Tenant = '3endt.com'; Device = '11111111-1111-1111-1111-111111111111' }
        @{ Tenant = 'aspendora.com'; Device = '44444444-4444-4444-4444-444444444444' }
    ) {
        param($Tenant, $Device)
        Mock Invoke-CippControlRIntegrationRequest { [pscustomobject]@{ Status = 200; Data = [pscustomobject]@{ controlRDeviceId = $script:Cid; cippTenantId = $Tenant; intuneManagedDeviceId = $Device } } }
        (Invoke-ExecControlRApprovedScript -Request (New-Req -Body $script:RunBody)).StatusCode | Should -Be 409
        Should -Invoke Invoke-CippControlRIntegrationRequest -Times 1 -Exactly
    }

    It 'starts the approved script by its id and logs it as CIPP integration' {
        $R = Invoke-ExecControlRApprovedScript -Request (New-Req -Body $script:RunBody)
        $R.StatusCode | Should -Be 200
        $R.Body.RunId | Should -Be $script:Rid
        Should -Invoke Invoke-CippControlRIntegrationRequest -ParameterFilter { $Path -eq "devices/$($script:Cid)/run/3833ef03-9fa5-4034-952d-7e84db85973d" } -Times 1 -Exactly
        Should -Invoke Write-LogMessage -ParameterFilter { $message -like 'CIPP integration: started*' -and $Sev -eq 'Info' } -Times 1 -Exactly
    }

    It 'reports and logs a ControlR refusal' {
        Mock Invoke-CippControlRIntegrationRequest {
            if ($Path -eq 'resolve') { return [pscustomobject]@{ Status = 200; Data = [pscustomobject]@{ controlRDeviceId = $script:Cid; cippTenantId = 'aspendora.com'; intuneManagedDeviceId = $script:Mid } } }
            [pscustomobject]@{ Status = 403; Data = $null; Message = 'ControlR returned HTTP 403.' }
        }
        (Invoke-ExecControlRApprovedScript -Request (New-Req -Body $script:RunBody)).StatusCode | Should -Be 403
        Should -Invoke Write-LogMessage -ParameterFilter { $Sev -eq 'Error' } -Times 1 -Exactly
    }

    It 'rejects a RunId that is not a GUID' {
        (Invoke-ExecControlRApprovedScript -Request (New-Req -Body @{ Action = 'Status'; RunId = '../users' })).StatusCode | Should -Be 400
        Should -Invoke Invoke-CippControlRIntegrationRequest -Times 0 -Exactly
    }

    It 'returns run status and output' {
        Mock Invoke-CippControlRIntegrationRequest { [pscustomobject]@{ Status = 200; Data = [pscustomobject]@{ id = $script:Rid; status = 'Completed' } } }
        $R = Invoke-ExecControlRApprovedScript -Request (New-Req -Body @{ Action = 'Status'; RunId = $script:Rid })
        $R.StatusCode | Should -Be 200
        $R.Body.Results.status | Should -Be 'Completed'
    }

    It 'rejects an unknown action' {
        (Invoke-ExecControlRApprovedScript -Request (New-Req -Body @{ Action = 'Delete' })).StatusCode | Should -Be 400
    }
}

Describe 'Invoke-CippControlRIntegrationRequest' {
    BeforeAll {
        . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))) 'Modules/CippExtensions/Public/ControlR/Invoke-CippControlRIntegrationRequest.ps1')
    }

    It 'fails plainly without a token and calls nothing' {
        Mock Get-ExtensionAPIKey { $null }
        Mock Invoke-RestMethod {}
        (Invoke-CippControlRIntegrationRequest -Method GET -Path 'runs/x').Status | Should -Be 500
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'sends the token only in the header, to the integration base URL' {
        Mock Get-ExtensionAPIKey { 'secret-value' }
        Mock Invoke-RestMethod { $script:Req = @{ Uri = $Uri; Headers = $Headers; Body = $Body }; Set-Variable -Name StatusCode -Value 200 -Scope 1; [pscustomobject]@{ ok = $true } }
        Invoke-CippControlRIntegrationRequest -Method POST -Path 'resolve' -Body @{ intuneManagedDeviceId = 'a' } | Out-Null
        $script:Req.Uri | Should -Be 'https://control.aspendora.com/api/integration/resolve'
        $script:Req.Headers['x-personal-token'] | Should -Be 'secret-value'
        $script:Req.Body | Should -Not -Match 'secret-value'
    }

    It 'turns a connection failure into a 502 that does not hold the token' {
        Mock Get-ExtensionAPIKey { 'secret-value' }
        Mock Invoke-RestMethod { throw 'connection refused' }
        $R = Invoke-CippControlRIntegrationRequest -Method GET -Path 'runs/x'
        $R.Status | Should -Be 502
        $R.Message | Should -Not -Match 'secret-value'
    }
}
