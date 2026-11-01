# Aspendora fork (Vikunja CIPP-22 / CIPP-24): the Graph / DNS readers behind ListEnrollmentDiscovery,
# ListDriverUpdateQueue, the DriverUpdatesBlocked alert and the DriverUpdateProfile standard. Response shapes are
# the ones observed live in aspendora.com / 3endt.com on 2026-10-31.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Ops = Join-Path $RepoRoot 'Modules/CIPPCore/Public/IntuneOps'
    foreach ($Name in 'Test-CIPPManagedDeviceActive', 'Test-CIPPEnrollmentDiscovery', 'Get-CIPPEnrollmentDiscovery', 'Get-CIPPDriverUpdateQueue', 'Get-CIPPDriverBlockingPolicies') {
        . (Join-Path $Ops "$Name.ps1")
    }
    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $AsApp) }
    function New-GraphBulkRequest { [CmdletBinding()] param($Requests, $tenantid) }
    function Resolve-DnsHttpsQuery { [CmdletBinding()] param($Domain, $RecordType) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
}

Describe 'Get-CIPPEnrollmentDiscovery' {
    BeforeEach {
        Mock New-GraphGetRequest {
            if ($uri -match 'mobileDeviceManagementPolicies') { return [pscustomobject]@{ appliesTo = 'selected'; includedGroups = @([pscustomobject]@{ id = 'g1'; displayName = 'Intune Users' }) } }
            if ($uri -match 'managedDevices') {
                return @(
                    [pscustomobject]@{ id = 'd1'; deviceName = 'HYB1'; joinType = 'hybridAzureADJoined'; deviceEnrollmentType = 'windowsCoManagement'; managementState = 'managed' }
                    [pscustomobject]@{ id = 'd2'; deviceName = 'AAD1'; joinType = 'azureADJoined'; deviceEnrollmentType = 'windowsAzureADJoin'; managementState = 'managed' }
                    [pscustomobject]@{ id = 'd3'; deviceName = 'GONE'; joinType = 'hybridAzureADJoined'; deviceEnrollmentType = 'windowsCoManagement'; managementState = 'retireIssued' }
                )
            }
            if ($uri -match '/domains') {
                return @(
                    [pscustomobject]@{ id = 'contoso.com'; isVerified = $true; supportedServices = @('Email', 'Intune') }
                    [pscustomobject]@{ id = 'contoso.onmicrosoft.com'; isVerified = $true; isInitial = $true; supportedServices = @('Email') }
                    [pscustomobject]@{ id = 'ABC123.smtp.exclaimer.cloud'; isVerified = $true; supportedServices = @() }
                    [pscustomobject]@{ id = 'unverified.com'; isVerified = $false; supportedServices = @('Email') }
                )
            }
        }
        Mock Resolve-DnsHttpsQuery {
            $script:Looked += @($Domain)
            if ($Domain -eq 'enterpriseenrollment.contoso.com') { return [pscustomobject]@{ Status = 0; Answer = @([pscustomobject]@{ name = $Domain; type = 5; data = 'enterpriseenrollment-s.manage.microsoft.com.' }) } }
            return [pscustomobject]@{ Status = 3 }
        }
        $script:Looked = @()
    }

    It 'checks only custom verified domains with services, and reads both CNAMEs' {
        $R = Get-CIPPEnrollmentDiscovery -TenantFilter 'contoso.com'
        $script:Looked | Should -Be @('enterpriseenrollment.contoso.com', 'enterpriseregistration.contoso.com')
        $R.Domains[0].EnrollmentTarget | Should -Be 'enterpriseenrollment-s.manage.microsoft.com'
        $R.Domains[0].RegistrationTarget | Should -Be ''
    }

    It 'counts Windows and hybrid GPO devices, ignoring retired ones, and returns findings' {
        $R = Get-CIPPEnrollmentDiscovery -TenantFilter 'contoso.com'
        $R.MdmScope | Should -Be 'selected'
        $R.MdmScopeGroups | Should -Be @('Intune Users')
        $R.WindowsDeviceCount | Should -Be 2
        $R.HybridDeviceCount | Should -Be 1
        $R.Findings.Category | Should -Contain 'CnameWithNarrowScope'
        $R.Findings.Category | Should -Contain 'HybridDependsOnScope'
        $R.Findings.Category | Should -Contain 'RegistrationMissing'
    }

    It 'records a failed DNS lookup as unknown' {
        Mock Resolve-DnsHttpsQuery { throw 'resolver timeout' }
        $R = Get-CIPPEnrollmentDiscovery -TenantFilter 'contoso.com'
        $R.Domains[0].LookupError | Should -BeTrue
        $R.Findings.Category | Should -Not -Contain 'CnameMissing'
        $R.Errors | Should -Match 'DNS lookup for contoso.com'
    }

    It 'keeps going when the MDM scope cannot be read' {
        Mock New-GraphGetRequest { if ($uri -match 'mobileDeviceManagementPolicies') { throw 'Forbidden' } else { @() } }
        $R = Get-CIPPEnrollmentDiscovery -TenantFilter 'contoso.com'
        $R.MdmScope | Should -Be 'unknown'
        $R.Errors | Should -Match '^MDM user scope:'
    }
}

Describe 'Get-CIPPDriverUpdateQueue' {
    It 'reads needsReview inventories per profile with a server-side filter' {
        Mock New-GraphGetRequest {
            @(
                [pscustomobject]@{ id = 'p1'; displayName = 'Windows Autopatch Driver Update Policy - G - Last'; description = 'Driver update policy, created by Windows Autopatch'; approvalType = 'automatic'; deploymentDeferralInDays = 11 }
                [pscustomobject]@{ id = 'p2'; displayName = 'Broken'; approvalType = 'manual' }
            )
        }
        Mock New-GraphBulkRequest {
            $script:Requests = $Requests
            @(
                [pscustomobject]@{ id = 'p1'; status = 200; body = [pscustomobject]@{ value = @(
                            [pscustomobject]@{ id = 'drv1'; name = 'Intel BT'; version = '1'; approvalStatus = 'needsReview'; applicableDeviceCount = 30; deployDateTime = '0001-01-01T00:00:00Z' }
                            [pscustomobject]@{ id = 'drv2'; name = 'Dell FW'; version = '2'; approvalStatus = 'needsReview'; applicableDeviceCount = 1; deployDateTime = '0001-01-01T00:00:00Z' }
                        ) } }
                [pscustomobject]@{ id = 'p2'; status = 403; body = [pscustomobject]@{ error = @{ message = 'Forbidden' } } }
            )
        }
        $R = Get-CIPPDriverUpdateQueue -TenantFilter 'contoso.com'
        $script:Requests[0].url | Should -Match 'driverInventories\?\$filter=approvalStatus%20eq%20''needsReview''$'
        $R.Available | Should -BeTrue
        @($R.Drivers.DriverId) | Should -Be @('drv1', 'drv2')
        $R.Drivers[0].Tenant | Should -Be 'contoso.com'
        $R.Drivers[0].ProfileId | Should -Be 'p1'
        $R.Drivers[0].Autopatch | Should -BeTrue
        $R.Drivers[0].DeployDate | Should -Be ''
        ($R.Profiles | Where-Object Id -EQ 'p2').Inventory | Should -Be 'Unavailable'
        $R.Errors | Should -Match 'Broken'
    }

    It 'reads everything for Status all' {
        Mock New-GraphGetRequest { @([pscustomobject]@{ id = 'p1'; displayName = 'P' }) }
        Mock New-GraphBulkRequest { $script:Requests = $Requests; @() }
        $null = Get-CIPPDriverUpdateQueue -TenantFilter 'contoso.com' -Status all
        $script:Requests[0].url | Should -Match 'driverInventories$'
    }

    It 'marks a tenant without driver management as unavailable, not empty' {
        Mock New-GraphGetRequest { throw 'Forbidden' }
        $R = Get-CIPPDriverUpdateQueue -TenantFilter 'contoso.com'
        $R.Available | Should -BeFalse
        $R.Errors[0] | Should -Match 'E3/E5'
    }
}

Describe 'Get-CIPPDriverBlockingPolicies' {
    It 'finds rings with drivers excluded and catalog policies excluding WU drivers' {
        Mock New-GraphGetRequest {
            if ($uri -match 'deviceConfigurations') {
                return @(
                    [pscustomobject]@{ id = 'r1'; displayName = 'Ring Block'; driversExcluded = $true; assignments = @(@{ id = 'a' }) }
                    [pscustomobject]@{ id = 'r2'; displayName = 'Ring Allow'; driversExcluded = $false; assignments = @() }
                )
            }
            return @(
                [pscustomobject]@{ id = 'c1'; name = 'Cat Block'; platforms = 'windows10'; technologies = 'mdm'; assignments = @() }
                [pscustomobject]@{ id = 'c2'; name = 'Cat Allow'; platforms = 'windows10'; technologies = 'mdm'; assignments = @(@{ id = 'a' }) }
                [pscustomobject]@{ id = 'c3'; name = 'macOS'; platforms = 'macOS'; technologies = 'mdm'; assignments = @() }
            )
        }
        Mock New-GraphBulkRequest {
            $script:Requests = $Requests
            $Setting = { param($Value) [pscustomobject]@{ settingInstance = [pscustomobject]@{ settingDefinitionId = 'device_vendor_msft_policy_config_update_excludewudriversinqualityupdate'; choiceSettingValue = [pscustomobject]@{ value = $Value } } } }
            @(
                [pscustomobject]@{ id = 'c1'; status = 200; body = [pscustomobject]@{ value = @(& $Setting 'device_vendor_msft_policy_config_update_excludewudriversinqualityupdate_1') } }
                [pscustomobject]@{ id = 'c2'; status = 200; body = [pscustomobject]@{ value = @(& $Setting 'device_vendor_msft_policy_config_update_excludewudriversinqualityupdate_0') } }
            )
        }
        $R = Get-CIPPDriverBlockingPolicies -TenantFilter 'contoso.com'
        @($R.Findings.Id) | Should -Be @('Ring|r1', 'Catalog|c1')
        ($R.Findings | Where-Object Id -EQ 'Ring|r1').Assigned | Should -BeTrue
        ($R.Findings | Where-Object Id -EQ 'Catalog|c1').Assigned | Should -BeFalse
        @($script:Requests.id) | Should -Not -Contain 'c3'
        $R.Errors.Count | Should -Be 0
    }
}
