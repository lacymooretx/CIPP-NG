# Pester tests for Get-CIPPPersonalDevices and Invoke-ListPersonalDevices (Vikunja CIPP-21).
# Pins: only personal devices are listed (even if Graph ignored the filter), Windows Entra registered = via work account,
# per-platform personalDeviceEnrollmentBlocked from the DEFAULT restriction only, the MDM-during-registration flag,
# unknown ($null, never $false) when a control cannot be read, the AllTenants cache path (ConvertFrom-Json re-typed
# dates, tenants with controls but no devices, empty lists that must not unroll to $null), and the endpoint contract.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Modules = Join-Path $RepoRoot 'Modules'
    # Azure Functions binding type does not exist outside the Functions host; define it before dot-sourcing.
    class HttpResponseContext {
        [object]$StatusCode
        [object]$Body
    }
    foreach ($Name in 'Get-CIPPPersonalDevices.ps1', 'Invoke-ListPersonalDevices.ps1') {
        $Path = Get-ChildItem -Path $Modules -Recurse -Filter $Name -File | Select-Object -First 1 -ExpandProperty FullName
        if (-not $Path) { throw "Could not locate $Name" }
        . $Path
    }

    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $AsApp) }
    function Get-CIPPDbItem { [CmdletBinding()] param($TenantFilter, $Type, [switch]$ByTenant) }
    function Get-CippException { [CmdletBinding()] param($Exception) @{ NormalizedError = "$Exception" } }
    function Write-LogMessage { [CmdletBinding()] param($headers, $API, $tenant, $message, $Sev, $LogData) }

    $script:Now = [datetime]::UtcNow
    function script:Ago([int]$Days) { $script:Now.AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ') }

    function script:New-Device {
        param([string]$Id, [string]$Os = 'Windows', [string]$Owner = 'personal', [string]$Join = 'azureADRegistered',
            [string]$Enroll = 'windowsAutoEnrollment', [int]$EnrolledDaysAgo = 100, [int]$SyncDaysAgo = 1, [string]$Compliance = 'compliant')
        [pscustomobject]@{
            id = $Id; deviceName = "DEV-$Id"; operatingSystem = $Os; osVersion = '10.0.26100'; userPrincipalName = "$Id@contoso.com"
            enrolledDateTime = (Ago $EnrolledDaysAgo); lastSyncDateTime = (Ago $SyncDaysAgo); deviceEnrollmentType = $Enroll
            joinType = $Join; managedDeviceOwnerType = $Owner; complianceState = $Compliance; managementState = 'managed'
        }
    }
    function script:New-Restriction {
        param($Windows = $true, $Ios = $true, [string]$Id = 'abc_DefaultPlatformRestrictions')
        [pscustomobject]@{
            id = $Id; deviceEnrollmentConfigurationType = 'platformRestrictions'
            windowsRestriction = [pscustomobject]@{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $Windows }
            iosRestriction = [pscustomobject]@{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $Ios }
            androidRestriction = [pscustomobject]@{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $false }
            androidForWorkRestriction = [pscustomobject]@{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $true }
            macOSRestriction = [pscustomobject]@{ platformBlocked = $false; personalDeviceEnrollmentBlocked = $true }
        }
    }
    function script:New-CacheRow([string]$Tenant, [string]$Type, $Object, [int]$N) {
        [pscustomobject]@{ PartitionKey = $Tenant; RowKey = "$Type-$N"; Data = ($Object | ConvertTo-Json -Depth 10 -Compress); Timestamp = [datetimeoffset]$script:Now }
    }
}

Describe 'Get-CIPPPersonalDevices (single tenant, live)' {
    BeforeEach {
        $script:Fixture = @{
            Devices    = @(
                (New-Device -Id 'p1'),
                (New-Device -Id 'p2' -Os 'iOS' -Join 'unknown' -Enroll 'appleUserEnrollment' -EnrolledDaysAgo 3 -Compliance 'noncompliant'),
                (New-Device -Id 'c1' -Owner 'company' -Join 'azureADJoined' -Enroll 'windowsAzureADJoin')
            )
            Configs    = @(
                [pscustomobject]@{ id = 'abc_DefaultLimit'; deviceEnrollmentConfigurationType = 'limit'; limit = 15 },
                (New-Restriction -Windows $false -Id 'grp_PlatformRestrictions'),
                (New-Restriction -Windows $true)
            )
            Mdm        = [pscustomobject]@{ id = '0000000a-0000-0000-c000-000000000000'; appliesTo = 'all'; isMdmEnrollmentDuringRegistrationDisabled = $false }
            ConfigFail = $false
            MdmFail    = $false
        }
        $script:Uris = [System.Collections.Generic.List[string]]::new()
        Mock New-GraphGetRequest {
            $script:Uris.Add($uri)
            if ($uri -like '*managedDevices*') { return $script:Fixture.Devices }
            if ($uri -like '*deviceEnrollmentConfigurations*') { if ($script:Fixture.ConfigFail) { throw 'Forbidden' }; return $script:Fixture.Configs }
            if ($uri -like '*mobileDeviceManagementPolicies*') { if ($script:Fixture.MdmFail) { throw 'Forbidden' }; return $script:Fixture.Mdm }
            throw "unexpected GET $uri"
        }
    }

    It 'filters on managedDeviceOwnerType in Graph and drops company devices even if the filter is ignored' {
        $R = Get-CIPPPersonalDevices -TenantFilter 'contoso.com'
        ($script:Uris | Where-Object { $_ -like '*managedDevices*' }) | Should -BeLike "*managedDeviceOwnerType eq 'personal'*"
        @($R.Devices).id | Should -Be @('p1', 'p2')
        $R.Source | Should -Be 'live'
    }

    It 'flags a Windows Entra registered device as enrolled via a work account, and labels the enrollment type' {
        $R = Get-CIPPPersonalDevices -TenantFilter 'contoso.com'
        $P1 = $R.Devices | Where-Object id -EQ 'p1'
        $P1.viaWorkAccount | Should -BeTrue
        $P1.enrollmentType | Should -Be 'Windows automatic enrollment (work account added)'
        ($R.Devices | Where-Object id -EQ 'p2').viaWorkAccount | Should -BeFalse
    }

    It 'builds the tenant summary from the default restriction only and the MDM policy' {
        $S = @((Get-CIPPPersonalDevices -TenantFilter 'contoso.com').Tenants)[0]
        $S.PersonalDevices | Should -Be 2
        $S.Windows | Should -Be 1
        $S.iOS | Should -Be 1
        $S.WindowsViaWorkAccount | Should -Be 1
        $S.NewDevices | Should -Be 1
        $S.NonCompliant | Should -Be 1
        $S.PersonalBlockedWindows | Should -BeTrue
        $S.PersonalBlockedAndroid | Should -BeFalse
        $S.MdmEnrollmentDuringRegistrationDisabled | Should -BeFalse
        $S.MdmUserScope | Should -Be 'all'
        $S.DefaultRestrictionFound | Should -BeTrue
    }

    It 'honours newDays' {
        $S = @((Get-CIPPPersonalDevices -TenantFilter 'contoso.com' -NewDays 200).Tenants)[0]
        $S.NewDevices | Should -Be 2
    }

    It 'reports a control it cannot read as unknown, not as allowed, and records the error' {
        $script:Fixture.ConfigFail = $true
        $script:Fixture.MdmFail = $true
        $R = Get-CIPPPersonalDevices -TenantFilter 'contoso.com'
        $S = @($R.Tenants)[0]
        $S.PersonalBlockedWindows | Should -BeNullOrEmpty
        $S.MdmEnrollmentDuringRegistrationDisabled | Should -BeNullOrEmpty
        $S.DefaultRestrictionFound | Should -BeNullOrEmpty
        @($R.Errors).Count | Should -Be 2
        @($R.Devices).Count | Should -Be 2
    }

    It 'returns empty arrays, not $null, for a tenant with no personal devices' {
        $script:Fixture.Devices = @()
        $R = Get-CIPPPersonalDevices -TenantFilter 'contoso.com'
        , $R.Devices | Should -BeOfType [object[]]
        @($R.Devices).Count | Should -Be 0
        @($R.Tenants)[0].PersonalDevices | Should -Be 0
    }

    It 'throws when the device list itself cannot be read' {
        Mock New-GraphGetRequest { throw 'Forbidden' }
        { Get-CIPPPersonalDevices -TenantFilter 'contoso.com' } | Should -Throw
    }
}

Describe 'Get-CIPPPersonalDevices (AllTenants, cache)' {
    BeforeEach {
        $script:Cache = @{
            ManagedDevices                 = [ordered]@{
                'a.com' = [System.Collections.Generic.List[object]]@(
                    (New-CacheRow 'a.com' 'ManagedDevices' (New-Device -Id 'a1') 1),
                    (New-CacheRow 'a.com' 'ManagedDevices' (New-Device -Id 'a2' -Owner 'company') 2)
                )
            }
            DeviceEnrollmentConfigurations = [ordered]@{
                'a.com' = [System.Collections.Generic.List[object]]@((New-CacheRow 'a.com' 'DeviceEnrollmentConfigurations' (New-Restriction -Windows $false) 1))
                'b.com' = [System.Collections.Generic.List[object]]@((New-CacheRow 'b.com' 'DeviceEnrollmentConfigurations' (New-Restriction) 1))
            }
            MobileDeviceManagementPolicies = [ordered]@{
                'b.com' = [System.Collections.Generic.List[object]]@((New-CacheRow 'b.com' 'MobileDeviceManagementPolicies' ([pscustomobject]@{ id = 'x'; appliesTo = 'selected'; isMdmEnrollmentDuringRegistrationDisabled = $true }) 1))
            }
        }
        Mock Get-CIPPDbItem { $script:Cache[$Type] }
        Mock New-GraphGetRequest { throw 'AllTenants must not call Graph' }
    }

    It 'reads every tenant from the cache, including one with controls but no devices' {
        $R = Get-CIPPPersonalDevices -TenantFilter 'AllTenants'
        $R.Source | Should -Be 'cache'
        @($R.Tenants).Tenant | Should -Be @('a.com', 'b.com')
        @($R.Devices).id | Should -Be @('a1')
        @($R.Devices)[0].Tenant | Should -Be 'a.com'
        Should -Invoke New-GraphGetRequest -Times 0 -Exactly
    }

    It 'keeps per-tenant control state and marks an uncached control as unknown' {
        $R = Get-CIPPPersonalDevices -TenantFilter 'AllTenants'
        $A = $R.Tenants | Where-Object Tenant -EQ 'a.com'
        $B = $R.Tenants | Where-Object Tenant -EQ 'b.com'
        $A.PersonalBlockedWindows | Should -BeFalse
        $A.MdmEnrollmentDuringRegistrationDisabled | Should -BeNullOrEmpty
        $B.PersonalBlockedWindows | Should -BeTrue
        $B.MdmEnrollmentDuringRegistrationDisabled | Should -BeTrue
        $B.MdmUserScope | Should -Be 'selected'
        $B.PersonalDevices | Should -Be 0
    }

    It 'handles dates that ConvertFrom-Json re-typed as [datetime]' {
        $R = Get-CIPPPersonalDevices -TenantFilter 'AllTenants'
        $D = @($R.Devices)[0]
        $D.enrolledDateTime | Should -Not -BeNullOrEmpty
        $D.daysSinceSync | Should -BeIn @(0, 1, 2)
        $D.isNew | Should -BeFalse
    }

    It 'records a failed cache read and still returns the other types' {
        Mock Get-CIPPDbItem { if ($Type -eq 'MobileDeviceManagementPolicies') { throw 'table offline' }; $script:Cache[$Type] }
        $R = Get-CIPPPersonalDevices -TenantFilter 'AllTenants'
        (@($R.Errors) -join '; ') | Should -Match 'MobileDeviceManagementPolicies'
        @($R.Devices).id | Should -Be @('a1')
    }
}

Describe 'Invoke-ListPersonalDevices' {
    It 'rejects a request without tenantFilter' {
        $R = Invoke-ListPersonalDevices -Request ([pscustomobject]@{ Query = [pscustomobject]@{}; Params = @{ CIPPEndpoint = 'ListPersonalDevices' }; Headers = @{} }) -TriggerMetadata $null
        $R.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
    }

    It 'passes tenantFilter and newDays through' {
        Mock Get-CIPPPersonalDevices { [pscustomobject]@{ Tenant = $TenantFilter; NewDays = $NewDays } }
        $R = Invoke-ListPersonalDevices -Request ([pscustomobject]@{ Query = [pscustomobject]@{ tenantFilter = 'contoso.com'; newDays = '7' }; Params = @{ CIPPEndpoint = 'ListPersonalDevices' }; Headers = @{} }) -TriggerMetadata $null
        $R.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $R.Body.NewDays | Should -Be 7
    }

    It 'returns 500, not 200, when the report fails' {
        Mock Get-CIPPPersonalDevices { throw 'Forbidden' }
        Mock Write-LogMessage {}
        $R = Invoke-ListPersonalDevices -Request ([pscustomobject]@{ Query = [pscustomobject]@{ tenantFilter = 'contoso.com' }; Params = @{ CIPPEndpoint = 'ListPersonalDevices' }; Headers = @{} }) -TriggerMetadata $null
        $R.StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
    }
}
