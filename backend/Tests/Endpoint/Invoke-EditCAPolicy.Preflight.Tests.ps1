# Aspendora fork (Vikunja CIPP-5): the "Enable Policy" action (EditCAPolicy State=Enabled) is gated by the CA pre-flight.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Invoke-EditCAPolicy.ps1' -File | Select-Object -First 1 -ExpandProperty FullName

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke($null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext { [object]$StatusCode; [object]$Body }

    function New-GraphPOSTRequest { [CmdletBinding()] param($uri, $tenantid, $type, $body, $asapp) $script:Patched = $body }
    function Write-LogMessage { [CmdletBinding()] param($headers, $API, $tenant, $message, $Sev, $LogData) }
    function Get-CippException { [CmdletBinding()] param($Exception) [pscustomobject]@{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Invoke-CIPPCAPreflight { [CmdletBinding()] param($TenantFilter, $PolicyId, $Headers) $script:Calls++; if ($script:Throw) { throw 'Graph down' }; $script:Result }
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/CAPreflight/Resolve-CIPPCAPreflightGate.ps1')
    . $FunctionPath

    function Send ($State, $Override) {
        $script:Patched = $null
        $Body = [pscustomobject]@{ tenantFilter = 'contoso.com'; GUID = 'p1'; State = $State }
        if ($null -ne $Override) { $Body | Add-Member -NotePropertyName PreflightOverride -NotePropertyValue $Override }
        Invoke-EditCAPolicy -Request @{ Params = @{ CIPPEndpoint = 'EditCAPolicy' }; Headers = @{}; Query = @{}; Body = $Body }
    }
}

Describe 'Invoke-EditCAPolicy pre-flight gate' {
    BeforeEach {
        $script:Calls = 0; $script:Throw = $false
        $script:Result = [pscustomobject]@{ Passed = $false; PolicyName = 'P'; Checks = @([pscustomobject]@{ Check = 'Break-glass accounts excluded'; Status = 'Fail'; Message = 'bg in scope' }) }
    }

    It 'blocks Enabled (the list page sends "Enabled") with 409 and does not PATCH' {
        $R = Send 'Enabled'
        $R.StatusCode | Should -Be ([System.Net.HttpStatusCode]::Conflict)
        $script:Patched | Should -BeNullOrEmpty
    }

    It 'enables with the override ticked' {
        (Send 'Enabled' $true).StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:Patched | Should -Match 'Enabled'
    }

    It 'blocks when the pre-flight cannot run, unless overridden' {
        $script:Throw = $true
        (Send 'Enabled').StatusCode | Should -Be ([System.Net.HttpStatusCode]::Conflict)
        (Send 'Enabled' $true).StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
    }

    It 'does not run for disable, report-only or rename' {
        (Send 'Disabled').StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        (Send 'enabledForReportingButNotEnforced').StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:Calls | Should -Be 0
    }
}
