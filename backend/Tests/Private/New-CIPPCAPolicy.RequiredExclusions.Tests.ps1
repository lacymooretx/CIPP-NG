# Pester tests for how New-CIPPCAPolicy handles excluded apps with no service principal (Vikunja CIPP-53).
#   - an ordinary one is still dropped, and that is now logged;
#   - the Authenticator Credential Registration app is provisioned instead, and a failure stops the deployment,
#     because deploying without it blocks passkey registration and looks like a success.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Functions/Format-CIPPCAPolicy.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Functions/Test-IsGuid.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Functions/Format-CIPPNamedLocationRange.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/Remove-ODataProperties.ps1')

    $script:Required = '6aa00308-ea33-4caa-90d6-ae905d8cb51b'
    $script:Other = 'ea890292-c8c8-4433-b5ea-b09d0668e1a6'
    $script:Existing = '11111111-1111-1111-1111-111111111111'

    function Get-CIPPTextReplacement { [CmdletBinding()] param($TenantFilter, $Text, [switch]$EscapeForJson) $Text }
    function New-CIPPDbRequest { param($TenantFilter, $Type, $Fields) }
    function New-GraphPOSTRequest {
        [CmdletBinding()] param($uri, $tenantid, $type, $body, $asApp, $ScheduleRetry)
        $script:GraphWrites.Add([pscustomobject]@{ Uri = $uri; Type = $type; Body = $body })
        [pscustomobject]@{ id = 'created-policy-id' }
    }
    function New-GraphGETRequest {
        [CmdletBinding()] param($uri, $tenantid, $asApp, [switch]$ComplexFilter)
        if ($uri -match 'servicePrincipals') { return $script:TenantSps }
        if ($uri -match 'namedLocations') { return @() }
        throw "Unexpected live Graph GET in test: $uri"
    }
    function New-GraphBulkRequest { [CmdletBinding()] param($Requests, $tenantid, $asapp) @() }
    function New-CIPPGroup { param($GroupObject, $TenantFilter, $APIName) throw 'New-CIPPGroup should not be called' }
    function Get-CippException { [CmdletBinding()] param($Exception) [pscustomobject]@{ NormalizedError = "$Exception" } }
    function Write-LogMessage {
        [CmdletBinding()] param($API, $tenant, $TenantFilter, $Headers, $message, $sev, $LogData)
        $script:Logs.Add([pscustomobject]@{ Message = $message; Sev = $sev })
    }
    function Confirm-CIPPServicePrincipal {
        [CmdletBinding()] param($TenantFilter, $AppId, [switch]$Provision)
        $script:ConfirmCalls.Add([pscustomobject]@{ AppId = $AppId; Provision = [bool]$Provision })
        $script:ConfirmResult
    }

    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/New-CIPPCAPolicy.ps1')

    function Invoke-TestDeploy {
        param([string[]]$Exclusions, [switch]$UsePreloaded)
        $Template = [pscustomobject]@{
            displayName   = 'CIPP-7 test'
            state         = 'disabled'
            conditions    = [pscustomobject]@{
                users          = [pscustomobject]@{ includeRoles = @('62e90394-69f5-4237-9190-012177145e10') }
                applications   = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = $Exclusions }
                clientAppTypes = @('all')
            }
            grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('mfa') }
        } | ConvertTo-Json -Depth 10
        $Params = @{ RawJSON = $Template; TenantFilter = 'customer.example.com'; State = 'disabled'; Overwrite = $true; PreloadedCAPolicies = @([pscustomobject]@{ id = 'x'; displayName = 'Unrelated' }) }
        if ($UsePreloaded) { $Params.PreloadedServicePrincipals = $script:TenantSps }
        $null = New-CIPPCAPolicy @Params
        $Write = $script:GraphWrites | Where-Object { $_.Uri -match '/policies$' } | Select-Object -Last 1
        @(($Write.Body | ConvertFrom-Json).conditions.applications.excludeApplications)
    }
}

Describe 'New-CIPPCAPolicy excluded applications' {
    BeforeEach {
        $script:GraphWrites = [System.Collections.Generic.List[object]]::new()
        $script:Logs = [System.Collections.Generic.List[object]]::new()
        $script:ConfirmCalls = [System.Collections.Generic.List[object]]::new()
        $script:TenantSps = @([pscustomobject]@{ appId = $script:Existing })
        $script:ConfirmResult = [pscustomobject]@{ State = 'Created'; Present = $true; Created = $true; Error = $null }
    }

    It 'keeps an app that has a service principal, and logs nothing' {
        Invoke-TestDeploy -Exclusions @($script:Existing) | Should -Be @($script:Existing)
        @($script:Logs | Where-Object Message -Match 'dropped').Count | Should -Be 0
        $script:ConfirmCalls.Count | Should -Be 0
    }

    It 'still drops an ordinary app with no service principal, and now logs a warning naming it' {
        Invoke-TestDeploy -Exclusions @($script:Existing, $script:Other) | Should -Be @($script:Existing)
        $Log = @($script:Logs | Where-Object Message -Match 'dropped')
        $Log.Count | Should -Be 1
        $Log[0].Sev | Should -Be 'Warning'
        $Log[0].Message | Should -Match $script:Other
        $Log[0].Message | Should -Match 'CIPP-7 test'
        $script:ConfirmCalls.Count | Should -Be 0
    }

    It 'provisions the required app rather than dropping it, and logs that' {
        Invoke-TestDeploy -Exclusions @($script:Required) | Should -Be @($script:Required)
        $script:ConfirmCalls[0].AppId | Should -Be $script:Required
        $script:ConfirmCalls[0].Provision | Should -BeTrue
        @($script:Logs | Where-Object Message -Match 'dropped').Count | Should -Be 0
        @($script:Logs | Where-Object Message -Match 'Provisioned').Count | Should -Be 1
    }

    It 'keeps the required app when a stale preloaded list misses it, without claiming to have created it' {
        $script:ConfirmResult = [pscustomobject]@{ State = 'Present'; Present = $true; Created = $false; Error = $null }
        Invoke-TestDeploy -Exclusions @($script:Required) -UsePreloaded | Should -Be @($script:Required)
        @($script:Logs | Where-Object Message -Match 'Provisioned').Count | Should -Be 0
    }

    It 'keeps it while a new service principal is still waiting on the read-back' {
        $script:ConfirmResult = [pscustomobject]@{ State = 'CreatedPendingReadBack'; Present = $true; Created = $true; Error = $null }
        Invoke-TestDeploy -Exclusions @($script:Required) | Should -Be @($script:Required)
    }

    It 'matches the required app regardless of case' {
        Invoke-TestDeploy -Exclusions @($script:Required.ToUpperInvariant()) | Should -Be @($script:Required.ToUpperInvariant())
        $script:ConfirmCalls.Count | Should -Be 1
    }

    It 'does not call provisioning when the required app is already listed' {
        $script:TenantSps = @([pscustomobject]@{ appId = $script:Required })
        Invoke-TestDeploy -Exclusions @($script:Required) | Should -Be @($script:Required)
        $script:ConfirmCalls.Count | Should -Be 0
    }

    It 'throws and writes no policy when provisioning fails' {
        $script:ConfirmResult = [pscustomobject]@{ State = 'Failed'; Present = $false; Created = $false; Error = 'Delegated: denied; AsApp: denied' }
        { Invoke-TestDeploy -Exclusions @($script:Required) } | Should -Throw '*could not be provisioned (Failed: Delegated: denied; AsApp: denied)*'
        @($script:GraphWrites | Where-Object { $_.Uri -match '/policies$' }).Count | Should -Be 0
    }

    It 'throws and writes no policy when the check could not read the tenant' {
        $script:ConfirmResult = [pscustomobject]@{ State = 'Unknown'; Present = $false; Created = $false; Error = 'Forbidden' }
        { Invoke-TestDeploy -Exclusions @($script:Required) } | Should -Throw '*Unknown: Forbidden*'
        @($script:GraphWrites | Where-Object { $_.Uri -match '/policies$' }).Count | Should -Be 0
    }
}
