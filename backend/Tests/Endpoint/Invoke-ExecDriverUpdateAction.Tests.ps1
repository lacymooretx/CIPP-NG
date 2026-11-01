# Aspendora fork (Vikunja CIPP-24): driver approve / decline / suspend. Input validation, the executeAction body, and
# the read-back that reports what Intune actually holds.

BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke($null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }
    function New-GraphPOSTRequest { [CmdletBinding()] param($uri, $tenantid, $type, $body, $ContentType) }
    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid) }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    . (Join-Path $BackendRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/MEM/Invoke-ExecDriverUpdateAction.ps1')

    $script:Profile = '8e1586dd-80d9-492f-8b3e-c68f42d4fdab'
    $script:Driver = '085728f2e8693ff9923f46ff7b1d254e0425a5a705a6d531700452d3c4f92c3d_db1a2b88-6458-429d-a3a6-7df2d5d701c0'
    function New-Req { param($Body) [pscustomobject]@{ Params = @{ CIPPEndpoint = 'ExecDriverUpdateAction' }; Headers = @{}; Query = @{}; Body = [pscustomobject]$Body } }
}

Describe 'Invoke-ExecDriverUpdateAction' {
    BeforeEach {
        Mock Write-LogMessage {}
        Mock New-GraphPOSTRequest { $script:Posted = @{ Uri = $uri; Body = ($body | ConvertFrom-Json) }; [pscustomobject]@{ successfulDriverIds = @($script:Driver); failedDriverIds = @(); notFoundDriverIds = @() } }
        Mock New-GraphGetRequest { @([pscustomobject]@{ id = $script:Driver; name = 'Intel Bluetooth'; approvalStatus = 'approved'; deployDateTime = '2026-10-31T20:00:00Z' }) }
    }

    It 'rejects <Name>' -ForEach @(
        @{ Name = 'AllTenants'; Body = @{ tenantFilter = 'AllTenants'; ProfileId = '8e1586dd-80d9-492f-8b3e-c68f42d4fdab'; DriverIds = 'x'; Action = 'Approve' } }
        @{ Name = 'a bad profile id'; Body = @{ tenantFilter = 'contoso.com'; ProfileId = 'nope'; DriverIds = 'x'; Action = 'Approve' } }
        @{ Name = 'an unknown action'; Body = @{ tenantFilter = 'contoso.com'; ProfileId = '8e1586dd-80d9-492f-8b3e-c68f42d4fdab'; DriverIds = 'x'; Action = 'Delete' } }
        @{ Name = 'no drivers'; Body = @{ tenantFilter = 'contoso.com'; ProfileId = '8e1586dd-80d9-492f-8b3e-c68f42d4fdab'; Action = 'Approve' } }
        @{ Name = 'a driver id with OData characters'; Body = @{ tenantFilter = 'contoso.com'; ProfileId = '8e1586dd-80d9-492f-8b3e-c68f42d4fdab'; DriverIds = "x' or 1 eq 1"; Action = 'Approve' } }
    ) {
        $R = Invoke-ExecDriverUpdateAction -Request (New-Req $Body)
        $R.StatusCode | Should -Be 400
        Should -Invoke New-GraphPOSTRequest -Times 0
    }

    It 'approves with a deployment date and reads the result back' {
        $R = Invoke-ExecDriverUpdateAction -Request (New-Req @{ tenantFilter = 'contoso.com'; ProfileId = $script:Profile; DriverIds = $script:Driver; Action = 'approve' })
        $R.StatusCode | Should -Be 200
        $script:Posted.Uri | Should -Match "windowsDriverUpdateProfiles/$($script:Profile)/executeAction$"
        $script:Posted.Body.actionName | Should -Be 'approve'
        @($script:Posted.Body.driverIds) | Should -Be @($script:Driver)
        $script:Posted.Body.deploymentDate | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        $R.Body.Results | Should -Match '1 now read back as approved'
    }

    It 'declines without a deployment date' {
        Mock New-GraphGetRequest { @([pscustomobject]@{ id = $script:Driver; name = 'Intel Bluetooth'; approvalStatus = 'declined' }) }
        $R = Invoke-ExecDriverUpdateAction -Request (New-Req @{ tenantFilter = 'contoso.com'; ProfileId = $script:Profile; DriverIds = @($script:Driver); Action = 'Decline' })
        $script:Posted.Body.actionName | Should -Be 'decline'
        $script:Posted.Body.PSObject.Properties.Name | Should -Not -Contain 'deploymentDate'
        $R.Body.Results | Should -Match 'read back as declined'
    }

    It 'warns when the read-back does not match' {
        Mock New-GraphGetRequest { @([pscustomobject]@{ id = $script:Driver; name = 'Intel Bluetooth'; approvalStatus = 'needsReview' }) }
        $R = Invoke-ExecDriverUpdateAction -Request (New-Req @{ tenantFilter = 'contoso.com'; ProfileId = $script:Profile; DriverIds = $script:Driver; Action = 'Approve' })
        $R.Body.Results | Should -Match '0 now read back as approved'
        Should -Invoke Write-LogMessage -ParameterFilter { $Sev -eq 'Warning' }
    }
}
