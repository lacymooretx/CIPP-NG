# Read-only device state endpoints for the CIPP and ControlR integration.
#
# The shapes below are copied from live Graph reads (2026-11-03), with identifiers replaced:
#  - states collections repeat each policy per context (each user plus "System account")
#  - settingStates sits only at {collection}/{policyId}/settingStates, with signed HRESULTs in errorCode
#  - compliance settings can have an empty 'setting' and only a settingName
# The contract these tests defend: a failure is an error, never an empty result.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Core = Join-Path $RepoRoot 'Modules/CIPPCore/Public'
    $Mem = Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/MEM'

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext { [int]$StatusCode; [object]$Body }

    # Routes: first regex that matches the uri wins. A scriptblock value runs (so it can throw).
    function New-GraphGetRequest {
        [CmdletBinding()]
        param($uri, $tenantid)
        $script:Requested.Add([string]$uri)
        foreach ($Route in $script:Routes) {
            if ($uri -match $Route.Pattern) {
                if ($Route.Respond -is [scriptblock]) { return (& $Route.Respond) }
                return $Route.Respond
            }
        }
        throw "Unrouted Graph request: $uri"
    }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) }
    function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = $Exception.Exception.Message } }
    function Get-CIPPIntuneEffectivePolicy {
        param($TenantFilter, $DeviceId)
        $script:EffectiveCalls.Add($DeviceId)
        if ($script:EffectiveThrows) { throw 'evaluation failed' }
        $script:EffectiveReport
    }

    . (Join-Path $Core 'ConvertTo-CIPPODataFilterValue.ps1')
    . (Join-Path $Core 'IntuneEffective/Resolve-CIPPManagedDevice.ps1')
    . (Join-Path $Core 'IntuneEffective/Get-CIPPManagedDevicePolicyStates.ps1')
    . (Join-Path $Mem 'Invoke-ListDeviceConfigurationState.ps1')
    . (Join-Path $Mem 'Invoke-ListDeviceComplianceState.ps1')
    . (Join-Path $Mem 'Invoke-ListDeviceEffectivePolicy.ps1')

    $script:ManagedId = '11111111-1111-1111-1111-111111111111'
    $script:EntraId = '22222222-2222-2222-2222-222222222222'
    $script:Device = [pscustomobject]@{
        id = $script:ManagedId; azureADDeviceId = $script:EntraId; deviceName = 'PC-01'; serialNumber = 'ABC1234'
        operatingSystem = 'Windows'; osVersion = '10.0.26200.9711'; userPrincipalName = 'user@contoso.com'
        complianceState = 'compliant'; complianceGracePeriodExpirationDateTime = '9999-12-31T23:59:59Z'; lastSyncDateTime = '2026-11-03T09:20:27Z'
    }

    function New-PolicyRow {
        param($Id, $Name, $State, $Upn = '', $Platform = 'windows10AndLater')
        [pscustomobject]@{
            id = $Id; displayName = $Name; version = 1; platformType = $Platform; state = $State; settingCount = 59
            userId = '00000000-0000-0000-0000-000000000000'; userPrincipalName = $Upn; settingStates = @()
        }
    }
    function New-SettingRow {
        param($InstanceId, $Setting, $State = 'compliant', $ErrorCode = 0, $ErrorDescription = '0', $Upn = '', $SettingName = 'Windows10CustomConfiguration')
        [pscustomobject]@{
            settingInstanceId = $InstanceId; setting = $Setting; settingName = $SettingName; state = $State
            errorCode = $ErrorCode; errorDescription = $ErrorDescription; currentValue = $null; userPrincipalName = $Upn
        }
    }
    function New-EffectiveRow {
        param($Id, $Name, $Type, $Family, $Status = 'Applies', $Applies = $true)
        [pscustomobject]@{
            PolicyId = $Id; PolicyName = $Name; PolicyType = $Type; Family = $Family; Platform = 'windows'; Status = $Status; Applies = $Applies
            TargetedVia = 'All Devices'; Filter = ''; FilterMode = ''; FilterResult = ''; ExcludedBy = ''; Notes = ''; DeviceStatus = ''
        }
    }
    # The two device-lookup routes every request crosses, resolving by Entra deviceId.
    function Get-DeviceFoundRoute { @{ Pattern = 'managedDevices\?\$filter='; Respond = @($script:Device) } }
    function New-DeviceRequest {
        param([hashtable]$Query)
        [pscustomobject]@{
            Params = @{ CIPPEndpoint = 'Test' }; Headers = @{}; Body = $null
            Query = [pscustomobject]$Query
        }
    }
    $script:Tenant = @{ tenantFilter = 'contoso.com'; DeviceId = $script:EntraId }
    function Reset-DeviceStateTest {
        $script:Requested = [System.Collections.Generic.List[string]]::new()
        $script:Routes = @()
        $script:EffectiveCalls = [System.Collections.Generic.List[string]]::new()
        $script:EffectiveThrows = $false
        $script:EffectiveReport = [pscustomobject]@{ Device = [pscustomobject]@{ DeviceName = 'PC-01' }; Results = @(); Errors = @() }
    }
}

Describe 'Resolve-CIPPManagedDevice' {
    BeforeEach { Reset-DeviceStateTest }

    It 'refuses a missing or all-tenants tenant' {
        (Resolve-CIPPManagedDevice -TenantFilter '' -DeviceId $script:EntraId).HttpStatus | Should -Be 400
        (Resolve-CIPPManagedDevice -TenantFilter 'AllTenants' -DeviceId $script:EntraId).HttpStatus | Should -Be 400
        $script:Requested.Count | Should -Be 0
    }

    It 'requires a device key' {
        (Resolve-CIPPManagedDevice -TenantFilter 'contoso.com').Status | Should -Be 'Invalid'
    }

    It 'refuses a non-GUID DeviceId and points at SerialNumber' {
        $Out = Resolve-CIPPManagedDevice -TenantFilter 'contoso.com' -DeviceId 'ABC1234'
        $Out.HttpStatus | Should -Be 400
        $Out.Message | Should -Match 'SerialNumber'
    }

    It 'refuses the empty GUID rather than matching every device without an Entra id' {
        (Resolve-CIPPManagedDevice -TenantFilter 'contoso.com' -DeviceId '00000000-0000-0000-0000-000000000000').HttpStatus | Should -Be 400
        $script:Requested.Count | Should -Be 0
    }

    It 'resolves an Entra deviceId through the filter without reading by id' {
        $script:Routes = @(Get-DeviceFoundRoute)
        $Out = Resolve-CIPPManagedDevice -TenantFilter 'contoso.com' -DeviceId $script:EntraId
        $Out.Status | Should -Be 'Found'
        $Out.Device.ManagedDeviceId | Should -Be $script:ManagedId
        $Out.Device.MatchedBy | Should -Be 'EntraDeviceId'
        $script:Requested.Count | Should -Be 1
    }

    It 'falls through to a by-id read for an Intune managed device id' {
        $script:Routes = @(
            @{ Pattern = 'managedDevices\?\$filter=azureADDeviceId'; Respond = @() }
            @{ Pattern = "managedDevices/$($script:ManagedId)"; Respond = $script:Device }
        )
        $Out = Resolve-CIPPManagedDevice -TenantFilter 'contoso.com' -DeviceId $script:ManagedId
        $Out.Status | Should -Be 'Found'
        $Out.Device.MatchedBy | Should -Be 'ManagedDeviceId'
    }

    It 'reports an unknown id as NotFound and keeps the text of the by-id failure' {
        $script:Routes = @(
            @{ Pattern = 'managedDevices\?\$filter=azureADDeviceId'; Respond = @() }
            @{ Pattern = 'managedDevices/'; Respond = { throw 'An error has occurred - Operation ID' } }
        )
        $Out = Resolve-CIPPManagedDevice -TenantFilter 'contoso.com' -DeviceId $script:ManagedId
        $Out.HttpStatus | Should -Be 404
        $Out.Detail | Should -Match 'An error has occurred'
        @($Out.Candidates).Count | Should -Be 0
    }

    It 'throws when the filter itself fails, so a Graph failure is never reported as not found' {
        $script:Routes = @(@{ Pattern = 'managedDevices\?\$filter='; Respond = { throw 'Forbidden' } })
        { Resolve-CIPPManagedDevice -TenantFilter 'contoso.com' -DeviceId $script:EntraId } | Should -Throw '*Forbidden*'
    }

    It 'resolves a serial number, escaping quotes for the OData filter' {
        $script:Routes = @(Get-DeviceFoundRoute)
        $Out = Resolve-CIPPManagedDevice -TenantFilter 'contoso.com' -SerialNumber " O'Neil 1 "
        $Out.Device.MatchedBy | Should -Be 'SerialNumber'
        $script:Requested[0] | Should -Match "serialNumber eq 'O%27%27Neil%201'"
    }

    It 'returns Ambiguous with candidates, newest sync first, when a serial repeats' {
        $Older = [pscustomobject]@{ id = 'older'; deviceName = 'A'; lastSyncDateTime = '2026-01-01T00:00:00Z' }
        $Newer = [pscustomobject]@{ id = 'newer'; deviceName = 'B'; lastSyncDateTime = '2026-11-01T00:00:00Z' }
        $script:Routes = @(@{ Pattern = 'serialNumber'; Respond = @($Older, $Newer) })
        $Out = Resolve-CIPPManagedDevice -TenantFilter 'contoso.com' -SerialNumber 'Defaultstring'
        $Out.HttpStatus | Should -Be 409
        @($Out.Candidates).Count | Should -Be 2
        $Out.Candidates[0].ManagedDeviceId | Should -Be 'newer'
        $Out.Device | Should -BeNullOrEmpty
    }

    It 'returns NotFound for an unknown serial' {
        $script:Routes = @(@{ Pattern = 'serialNumber'; Respond = @() })
        (Resolve-CIPPManagedDevice -TenantFilter 'contoso.com' -SerialNumber 'NOPE').HttpStatus | Should -Be 404
    }
}

Describe 'Get-CIPPManagedDevicePolicyStates' {
    BeforeEach {
        Reset-DeviceStateTest
        $script:Csp = "root\ccm\cimodels:CustomConfiguration.Key='./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditAuditPolicyChange',Type=20"
    }

    It 'collapses per-context rows to one policy with the worst state, keeping the contexts' {
        $script:Routes = @(
            @{ Pattern = 'settingStates$'; Respond = @() }
            @{ Pattern = 'deviceConfigurationStates$'; Respond = @(
                    (New-PolicyRow 'p1' 'Huntress' 'compliant' 'user@contoso.com')
                    (New-PolicyRow 'p1' 'Huntress' 'error' '')
                ) }
        )
        $Out = Get-CIPPManagedDevicePolicyStates -TenantFilter 't' -ManagedDeviceId 'd' -Collection deviceConfigurationStates
        @($Out.Results).Count | Should -Be 1
        $Out.Results[0].State | Should -Be 'error'
        @($Out.Results[0].Contexts.UserPrincipalName) | Should -Be @('System account', 'user@contoso.com')
    }

    It 'reads settings only for failing policies and returns only failing settings by default' {
        $script:Routes = @(
            @{ Pattern = 'bad/settingStates$'; Respond = @(
                    (New-SettingRow 'a' $script:Csp 'error' -2016281112 '2' 'user@contoso.com')
                    (New-SettingRow 'a' $script:Csp 'error' -2016281112 '2' '')
                    (New-SettingRow 'b' 'other' 'compliant')
                ) }
            @{ Pattern = 'deviceConfigurationStates$'; Respond = @((New-PolicyRow 'bad' 'Bad' 'error'), (New-PolicyRow 'good' 'Good' 'compliant')) }
        )
        $Out = Get-CIPPManagedDevicePolicyStates -TenantFilter 't' -ManagedDeviceId 'd' -Collection deviceConfigurationStates
        @($script:Requested | Where-Object { $_ -match 'settingStates' }).Count | Should -Be 1
        $Bad = $Out.Results | Where-Object PolicyId -EQ 'bad'
        @($Bad.Settings).Count | Should -Be 1
        $Bad.Settings[0].CspPath | Should -Be './Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditAuditPolicyChange'
        $Bad.Settings[0].ErrorCode | Should -Be -2016281112
        $Bad.Settings[0].ErrorCodeHex | Should -Be '0x87D1FDE8'
        $Bad.Settings[0].ErrorDescription | Should -Be '2'
        @($Bad.Settings[0].Contexts) | Should -Be @('System account', 'user@contoso.com')
        @(($Out.Results | Where-Object PolicyId -EQ 'good').Settings).Count | Should -Be 0
    }

    It 'orders failing policies first' {
        $script:Routes = @(
            @{ Pattern = 'settingStates$'; Respond = @() }
            @{ Pattern = 'deviceConfigurationStates$'; Respond = @((New-PolicyRow 'a' 'A' 'compliant'), (New-PolicyRow 'z' 'Z' 'error')) }
        )
        (Get-CIPPManagedDevicePolicyStates -TenantFilter 't' -ManagedDeviceId 'd' -Collection deviceConfigurationStates).Results[0].PolicyId | Should -Be 'z'
    }

    It 'returns every setting with -IncludeAllSettings, blanking the "0" description and zero code' {
        $script:Routes = @(
            @{ Pattern = 'settingStates$'; Respond = @(New-SettingRow 'b' './Vendor/MSFT/DeviceStatus/Antivirus/Status' 'compliant') }
            @{ Pattern = 'deviceCompliancePolicyStates$'; Respond = @(New-PolicyRow 'good' 'Good' 'compliant') }
        )
        $Out = Get-CIPPManagedDevicePolicyStates -TenantFilter 't' -ManagedDeviceId 'd' -Collection deviceCompliancePolicyStates -IncludeAllSettings
        $Setting = $Out.Results[0].Settings[0]
        $Setting.CspPath | Should -Be './Vendor/MSFT/DeviceStatus/Antivirus/Status'
        $Setting.ErrorDescription | Should -BeNullOrEmpty
        $Setting.ErrorCodeHex | Should -BeNullOrEmpty
    }

    It 'keeps a compliance setting that has no setting path, by its settingName' {
        $script:Routes = @(
            @{ Pattern = 'settingStates$'; Respond = @(
                    [pscustomobject]@{ setting = ''; settingName = 'Windows10CompliancePolicy.ActiveFirewallRequired'; state = 'nonCompliant'; errorCode = 0; errorDescription = '0'; userPrincipalName = '' }
                ) }
            @{ Pattern = 'deviceCompliancePolicyStates$'; Respond = @(New-PolicyRow 'c' 'Windows Compliance' 'nonCompliant') }
        )
        $Setting = (Get-CIPPManagedDevicePolicyStates -TenantFilter 't' -ManagedDeviceId 'd' -Collection deviceCompliancePolicyStates).Results[0].Settings[0]
        $Setting.SettingName | Should -Be 'Windows10CompliancePolicy.ActiveFirewallRequired'
        $Setting.CspPath | Should -BeNullOrEmpty
    }

    It 'throws when the states collection fails' {
        $script:Routes = @(@{ Pattern = 'deviceConfigurationStates$'; Respond = { throw 'HTTP 500' } })
        { Get-CIPPManagedDevicePolicyStates -TenantFilter 't' -ManagedDeviceId 'd' -Collection deviceConfigurationStates } | Should -Throw '*HTTP 500*'
    }

    It 'records an unreadable settingStates on the row and in Errors, and keeps the other policies' {
        $script:Routes = @(
            @{ Pattern = 'bad/settingStates$'; Respond = { throw 'HTTP 500' } }
            @{ Pattern = 'deviceConfigurationStates$'; Respond = @((New-PolicyRow 'bad' 'Bad' 'error'), (New-PolicyRow 'good' 'Good' 'compliant')) }
        )
        $Out = Get-CIPPManagedDevicePolicyStates -TenantFilter 't' -ManagedDeviceId 'd' -Collection deviceConfigurationStates
        @($Out.Results).Count | Should -Be 2
        ($Out.Results | Where-Object PolicyId -EQ 'bad').SettingsError | Should -Match 'HTTP 500'
        @($Out.Errors).Count | Should -Be 1
        $Out.Errors[0] | Should -Match "'Bad'"
    }

    It 'returns an empty result only when Graph really returned none' {
        $script:Routes = @(@{ Pattern = 'deviceConfigurationStates$'; Respond = @() })
        $Out = Get-CIPPManagedDevicePolicyStates -TenantFilter 't' -ManagedDeviceId 'd' -Collection deviceConfigurationStates
        @($Out.Results).Count | Should -Be 0
        @($Out.Errors).Count | Should -Be 0
    }
}

Describe 'Invoke-ListDeviceConfigurationState' {
    BeforeEach {
        Reset-DeviceStateTest
        $script:StateRoutes = @(
            @{ Pattern = 'settingStates$'; Respond = @() }
            @{ Pattern = 'deviceConfigurationStates$'; Respond = @((New-PolicyRow 'cfg' 'Windows Hello' 'compliant')) }
            (Get-DeviceFoundRoute)
        )
    }

    It 'returns 400 without calling Graph when no device is given' {
        $Out = Invoke-ListDeviceConfigurationState -Request (New-DeviceRequest @{ tenantFilter = 'contoso.com' })
        $Out.StatusCode | Should -Be 400
        $script:Requested.Count | Should -Be 0
    }

    It 'returns 404 for an unknown serial' {
        $script:Routes = @(@{ Pattern = 'serialNumber'; Respond = @() })
        (Invoke-ListDeviceConfigurationState -Request (New-DeviceRequest @{ tenantFilter = 'contoso.com'; SerialNumber = 'NOPE' })).StatusCode | Should -Be 404
    }

    It 'returns 500, not an empty list, when the state collection fails' {
        $script:Routes = @(
            @{ Pattern = 'deviceConfigurationStates$'; Respond = { throw 'An error has occurred' } }
            (Get-DeviceFoundRoute)
        )
        $Out = Invoke-ListDeviceConfigurationState -Request (New-DeviceRequest $script:Tenant)
        $Out.StatusCode | Should -Be 500
        $Out.Body.Results | Should -Match 'An error has occurred'
    }

    It 'joins assignment to state and adds applying profiles with no state as notReported' {
        $script:Routes = $script:StateRoutes
        $script:EffectiveReport.Results = @(
            (New-EffectiveRow 'cfg' 'Windows Hello' 'Device Configuration' 'DeviceConfigurations')
            (New-EffectiveRow 'cat' 'Bitlocker' 'Endpoint Security' 'ConfigurationPolicies')
            (New-EffectiveRow 'off' 'Filtered' 'Settings Catalog' 'ConfigurationPolicies' 'Filtered out' $false)
            (New-EffectiveRow 'app' 'Company Portal' 'App' 'MobileApps')
            (New-EffectiveRow 'cmp' 'Windows Compliance' 'Compliance Policy' 'deviceCompliancePolicies')
        )
        $Out = Invoke-ListDeviceConfigurationState -Request (New-DeviceRequest $script:Tenant)
        $Out.StatusCode | Should -Be 200
        $script:EffectiveCalls[0] | Should -Be $script:ManagedId
        @($Out.Body.Results.PolicyId | Sort-Object) | Should -Be @('cat', 'cfg', 'off')
        $Cfg = $Out.Body.Results | Where-Object PolicyId -EQ 'cfg'
        $Cfg.State | Should -Be 'compliant'
        $Cfg.Type | Should -Be 'Device Configuration'
        $Cfg.Assignment.TargetedVia | Should -Be 'All Devices'
        $Cat = $Out.Body.Results | Where-Object PolicyId -EQ 'cat'
        $Cat.State | Should -Be 'notReported'
        $Cat.StateSource | Should -BeNullOrEmpty
        $Out.Body.Summary.NotReported | Should -Be 1
        $Out.Body.Notes[0] | Should -Match 'unknown, not healthy'
        $Out.Body.Partial | Should -BeFalse
    }

    It 'skips the assignment evaluation when IncludeAssignments is the string false' {
        $script:Routes = $script:StateRoutes
        $Out = Invoke-ListDeviceConfigurationState -Request (New-DeviceRequest ($script:Tenant + @{ IncludeAssignments = 'false' }))
        $script:EffectiveCalls.Count | Should -Be 0
        $Out.Body.Results[0].Assignment | Should -BeNullOrEmpty
        $Out.Body.Notes[0] | Should -Match 'IncludeAssignments=false'
    }

    It 'returns all settings when IncludeSettings is the string true' {
        $script:Routes = $script:StateRoutes
        $null = Invoke-ListDeviceConfigurationState -Request (New-DeviceRequest ($script:Tenant + @{ IncludeSettings = 'true'; IncludeAssignments = 'false' }))
        @($script:Requested | Where-Object { $_ -match 'cfg/settingStates$' }).Count | Should -Be 1
    }

    It 'still returns state, marked Partial, when the assignment evaluation fails' {
        $script:Routes = $script:StateRoutes
        $script:EffectiveThrows = $true
        $Out = Invoke-ListDeviceConfigurationState -Request (New-DeviceRequest $script:Tenant)
        $Out.StatusCode | Should -Be 200
        $Out.Body.Partial | Should -BeTrue
        $Out.Body.Errors[0] | Should -Match 'evaluation failed'
        @($Out.Body.Results).Count | Should -Be 1
    }

    It 'carries evaluation errors through as Partial' {
        $script:Routes = $script:StateRoutes
        $script:EffectiveReport.Errors = @('Device group membership: Forbidden')
        $Out = Invoke-ListDeviceConfigurationState -Request (New-DeviceRequest $script:Tenant)
        $Out.Body.Partial | Should -BeTrue
        $Out.Body.Errors[0] | Should -Match 'Device group membership'
    }

    It 'keeps Results an array in the JSON for a single profile' {
        $script:Routes = $script:StateRoutes
        $Out = Invoke-ListDeviceConfigurationState -Request (New-DeviceRequest ($script:Tenant + @{ IncludeAssignments = 'false' }))
        ($Out.Body | ConvertTo-Json -Depth 8 -Compress) | Should -Match '"Results":\[\{'
    }
}

Describe 'Invoke-ListDeviceComplianceState' {
    BeforeEach { Reset-DeviceStateTest }

    It 'returns the device compliance state and policy rows with failing settings' {
        $script:Routes = @(
            @{ Pattern = 'cmp/settingStates$'; Respond = @(New-SettingRow 'a' './Vendor/MSFT/DeviceStatus/Antivirus/Status' 'nonCompliant') }
            @{ Pattern = 'deviceCompliancePolicyStates$'; Respond = @(New-PolicyRow 'cmp' 'Windows Compliance' 'nonCompliant') }
            (Get-DeviceFoundRoute)
        )
        $Out = Invoke-ListDeviceComplianceState -Request (New-DeviceRequest $script:Tenant)
        $Out.StatusCode | Should -Be 200
        $Out.Body.Device.ComplianceState | Should -Be 'compliant'
        $Out.Body.Device.ComplianceGracePeriodExpiration | Should -Be '9999-12-31T23:59:59Z'
        $Out.Body.Results[0].State | Should -Be 'nonCompliant'
        $Out.Body.Results[0].Settings[0].State | Should -Be 'nonCompliant'
        $Out.Body.Summary.Failing | Should -Be 1
        $Out.Body.Partial | Should -BeFalse
    }

    It 'never calls the assignment evaluation' {
        $script:Routes = @(
            @{ Pattern = 'deviceCompliancePolicyStates$'; Respond = @(New-PolicyRow 'cmp' 'Windows Compliance' 'compliant') }
            (Get-DeviceFoundRoute)
        )
        $null = Invoke-ListDeviceComplianceState -Request (New-DeviceRequest $script:Tenant)
        $script:EffectiveCalls.Count | Should -Be 0
    }

    It 'returns 500, not an empty list, when the collection fails' {
        $script:Routes = @(
            @{ Pattern = 'deviceCompliancePolicyStates$'; Respond = { throw 'Forbidden' } }
            (Get-DeviceFoundRoute)
        )
        $Out = Invoke-ListDeviceComplianceState -Request (New-DeviceRequest $script:Tenant)
        $Out.StatusCode | Should -Be 500
        $Out.Body.Results | Should -Match 'Forbidden'
    }

    It 'passes candidates back on an ambiguous serial' {
        $script:Routes = @(@{ Pattern = 'serialNumber'; Respond = @(
                    [pscustomobject]@{ id = 'a'; lastSyncDateTime = '2026-01-01T00:00:00Z' }
                    [pscustomobject]@{ id = 'b'; lastSyncDateTime = '2026-02-01T00:00:00Z' }
                ) })
        $Out = Invoke-ListDeviceComplianceState -Request (New-DeviceRequest @{ tenantFilter = 'contoso.com'; SerialNumber = 'Defaultstring' })
        $Out.StatusCode | Should -Be 409
        @($Out.Body.Candidates).Count | Should -Be 2
    }
}

Describe 'Invoke-ListDeviceEffectivePolicy' {
    BeforeEach { Reset-DeviceStateTest }

    It 'evaluates the resolved managed device when given a serial' {
        $script:Routes = @(Get-DeviceFoundRoute)
        $Out = Invoke-ListDeviceEffectivePolicy -Request (New-DeviceRequest @{ tenantFilter = 'contoso.com'; SerialNumber = 'ABC1234' })
        $Out.StatusCode | Should -Be 200
        $script:EffectiveCalls[0] | Should -Be $script:ManagedId
        $Out.Body.Device.MatchedBy | Should -Be 'SerialNumber'
        $Out.Body.Partial | Should -BeFalse
    }

    It 'marks a report carrying errors as Partial' {
        $script:Routes = @(Get-DeviceFoundRoute)
        $script:EffectiveReport.Errors = @('Settings overlap check: boom')
        (Invoke-ListDeviceEffectivePolicy -Request (New-DeviceRequest $script:Tenant)).Body.Partial | Should -BeTrue
    }

    It 'returns 500 when the evaluation fails' {
        $script:Routes = @(Get-DeviceFoundRoute)
        $script:EffectiveThrows = $true
        $Out = Invoke-ListDeviceEffectivePolicy -Request (New-DeviceRequest $script:Tenant)
        $Out.StatusCode | Should -Be 500
        $Out.Body.Results | Should -Match 'evaluation failed'
    }

    It 'returns 404 without evaluating an unknown device' {
        $script:Routes = @(@{ Pattern = 'serialNumber'; Respond = @() })
        $Out = Invoke-ListDeviceEffectivePolicy -Request (New-DeviceRequest @{ tenantFilter = 'contoso.com'; SerialNumber = 'NOPE' })
        $Out.StatusCode | Should -Be 404
        $script:EffectiveCalls.Count | Should -Be 0
    }
}

Describe 'Get-CIPPIntuneEffectivePolicy device status reads' {
    BeforeAll {
        . (Join-Path $Core 'IntuneEffective/Get-CIPPIntuneEffectivePolicy.ps1')
        function Get-CIPPIntunePolicyPlatform { param($OperatingSystem) 'windows' }
        function Get-CIPPIntuneAssignablePolicies { param($TenantFilter, [switch]$IncludeApps) [pscustomobject]@{ Policies = @(); Filters = @{}; Errors = @() } }
        function Resolve-CIPPIntuneAssignments { param($Policies, $DevicePlatform, $DeviceProperties, $DeviceGroupIds, $UserGroupIds, $HasUser, $UserName, $GroupNames, $Filters) [pscustomobject]@{ Rows = @(); PlatformSkipped = 0 } }
    }
    BeforeEach { Reset-DeviceStateTest }

    It 'reports a failed status read in Errors, so callers can mark the report Partial' {
        $script:Routes = @(
            @{ Pattern = 'deviceConfigurationStates'; Respond = { throw 'HTTP 500' } }
            @{ Pattern = 'deviceCompliancePolicyStates'; Respond = @() }
            @{ Pattern = "managedDevices/$($script:ManagedId)\?"; Respond = $script:Device }
            @{ Pattern = '/devices\?'; Respond = @() }
            @{ Pattern = 'windowsAutopilotDeviceIdentities'; Respond = @() }
        )
        $Report = Get-CIPPIntuneEffectivePolicy -TenantFilter 'contoso.com' -DeviceId $script:ManagedId
        @($Report.Errors | Where-Object { $_ -match 'Device status \(deviceConfigurationStates\).*HTTP 500' }).Count | Should -Be 1
        @($Report.Notes | Where-Object { $_ -match 'Device status' }).Count | Should -Be 0
    }
}

Describe 'Entrypoint contract' {
    BeforeEach { Reset-DeviceStateTest }

    It 'is read-only and uses the Endpoint.MEM.Read role' {
        foreach ($Name in 'Invoke-ListDeviceConfigurationState', 'Invoke-ListDeviceComplianceState', 'Invoke-ListDeviceEffectivePolicy') {
            $Source = Get-Content -Raw -Path (Join-Path $RepoRoot "Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/MEM/$Name.ps1")
            $Source | Should -Match '\.ROLE\s+Endpoint\.MEM\.Read'
            $Source | Should -Not -Match 'New-GraphPostRequest|New-GraphBulkRequest'
        }
    }
}
