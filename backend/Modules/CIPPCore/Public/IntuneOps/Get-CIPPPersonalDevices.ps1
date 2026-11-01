function Get-CIPPPersonalDevices {
    <#
    .SYNOPSIS
        Personally owned Intune devices per tenant, with the tenant's BYOD enrollment controls.
    .DESCRIPTION
        Read only. Shared by ListPersonalDevices (Endpoint > Reports > Personal Devices) and the PersonalDevices alert.

        Devices: managedDevices whose managedDeviceOwnerType is 'personal' (filtered by Graph and again client-side), with
        OS, user, enrolled date, last sync, enrollment type (deviceEnrollmentType) and join type, compliance, and a
        ViaWorkAccount flag for Windows devices that are Entra *registered* (joinType azureADRegistered), which is how a
        personal PC ends up enrolled when a user adds a work account under Settings > Accounts > Access work or school.

        Controls, per tenant:
          - personalDeviceEnrollmentBlocked per platform from the default platform restriction
            (deviceEnrollmentConfigurations id '*_DefaultPlatformRestrictions'; see the DefaultPlatformRestrictions standard).
            Group-assigned restrictions with a higher priority can override it for their members and are not evaluated.
          - isMdmEnrollmentDuringRegistrationDisabled and the MDM user scope (appliesTo) from beta
            policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000 (the
            MDMEnrollmentDuringRegistration standard).

        Single tenant: read live (three Graph GETs). AllTenants: read from the CIPP reporting DB cache (ManagedDevices,
        DeviceEnrollmentConfigurations, MobileDeviceManagementPolicies), so it is only as fresh as the last cache run.
        A control that could not be read is $null ("unknown"), never $false.
        Aspendora fork addition (Vikunja CIPP-21).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        # Devices enrolled within this many days are marked IsNew and counted in the summary.
        [int]$NewDays = 30,
        # Rows already read by the AllTenants path, keyed by cache type.
        [Parameter(DontShow = $true)]
        [hashtable]$DbItems
    )

    $Now = [datetime]::UtcNow

    if ($TenantFilter -eq 'AllTenants') {
        $Devices = [System.Collections.Generic.List[object]]::new()
        $Tenants = [System.Collections.Generic.List[object]]::new()
        $Errors = [System.Collections.Generic.List[string]]::new()
        $ByType = @{}
        foreach ($Type in 'ManagedDevices', 'DeviceEnrollmentConfigurations', 'MobileDeviceManagementPolicies') {
            try {
                $ByType[$Type] = Get-CIPPDbItem -TenantFilter 'allTenants' -Type $Type -ByTenant
            } catch {
                $ByType[$Type] = [ordered]@{}
                $Errors.Add("Cache read failed for ${Type}: $($_.Exception.Message)")
            }
        }
        # A tenant appears when any of the three caches holds rows for it, so a tenant with controls but no devices
        # still reports its control state.
        $Names = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($Map in $ByType.Values) { foreach ($Key in @($Map.Keys)) { [void]$Names.Add([string]$Key) } }
        foreach ($Name in $Names) {
            $Items = @{}
            foreach ($Type in @($ByType.Keys)) {
                # Assigned directly, not through `$x = if ...`, which would unroll an empty list to $null.
                $Items[$Type] = @()
                if ($ByType[$Type].Contains($Name)) { $Items[$Type] = $ByType[$Type][$Name] }
            }
            try {
                $One = Get-CIPPPersonalDevices -TenantFilter $Name -NewDays $NewDays -DbItems $Items
                foreach ($D in @($One.Devices)) { $Devices.Add($D) }
                foreach ($T in @($One.Tenants)) { $Tenants.Add($T) }
                foreach ($E in @($One.Errors)) { $Errors.Add("${Name}: $E") }
            } catch {
                $Errors.Add("${Name}: $($_.Exception.Message)")
            }
        }
        return [pscustomobject]@{
            Tenant  = 'AllTenants'
            Source  = 'cache'
            NewDays = $NewDays
            Tenants = @($Tenants)
            Devices = @($Devices)
            Errors  = @($Errors)
        }
    }

    $Errors = [System.Collections.Generic.List[string]]::new()

    function ConvertTo-UtcDate($Value) {
        if (-not $Value) { return $null }
        # Cache rows go through ConvertFrom-Json, which re-types ISO strings as [datetime]; live rows stay strings.
        try {
            if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
            return ([datetimeoffset][string]$Value).UtcDateTime
        } catch { return $null }
    }
    function ConvertFrom-CacheRow($Rows) {
        foreach ($Row in @($Rows)) {
            if (-not $Row -or [string]$Row.RowKey -like '*-Count') { continue }
            try { $Row.Data | ConvertFrom-Json -Depth 20 -ErrorAction Stop } catch { continue }
        }
    }

    $FromCache = $null -ne $DbItems
    $CacheTimestamp = $null
    $RawDevices = @()
    $Restriction = $null
    $MdmPolicy = $null
    $MdmRead = $false
    $RestrictionRead = $false

    if ($FromCache) {
        $RawDevices = @(ConvertFrom-CacheRow $DbItems['ManagedDevices'])
        $CacheTimestamp = (@($DbItems['ManagedDevices']) | Where-Object { $_.Timestamp } | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
        $Configs = @(ConvertFrom-CacheRow $DbItems['DeviceEnrollmentConfigurations'])
        if ($Configs.Count -gt 0) {
            $RestrictionRead = $true
            $Restriction = $Configs | Where-Object { [string]$_.id -like '*_DefaultPlatformRestrictions' } | Select-Object -First 1
        }
        $Policies = @(ConvertFrom-CacheRow $DbItems['MobileDeviceManagementPolicies'])
        if ($Policies.Count -gt 0) {
            $MdmRead = $true
            $MdmPolicy = $Policies | Select-Object -First 1
        }
    } else {
        $Select = 'id,deviceName,operatingSystem,osVersion,model,manufacturer,serialNumber,userPrincipalName,userDisplayName,enrolledDateTime,lastSyncDateTime,deviceEnrollmentType,joinType,managedDeviceOwnerType,complianceState,managementState'
        # The owner filter was verified live 2026-11-01 (aspendora.com: 12 devices, all company; filtered read returned none).
        $RawDevices = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=managedDeviceOwnerType eq 'personal'&`$select=$Select&`$top=999" -tenantid $TenantFilter)
        try {
            # -AsApp matches the DefaultPlatformRestrictions standard and the DeviceEnrollmentConfigurations cache.
            $Configs = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations?$top=999' -tenantid $TenantFilter -AsApp $true)
            $RestrictionRead = $true
            $Restriction = $Configs | Where-Object { [string]$_.id -like '*_DefaultPlatformRestrictions' } | Select-Object -First 1
        } catch {
            $Errors.Add("Enrollment restrictions: $((Get-CippException -Exception $_).NormalizedError)")
        }
        try {
            $MdmPolicy = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000' -tenantid $TenantFilter
            $MdmRead = $true
        } catch {
            $Errors.Add("MDM user scope policy: $((Get-CippException -Exception $_).NormalizedError)")
        }
    }

    # Platform -> property on the default platform restriction. $null = unknown (not read, or no default policy).
    $PlatformMap = [ordered]@{
        Windows        = 'windowsRestriction'
        iOS            = 'iosRestriction'
        Android        = 'androidRestriction'
        AndroidForWork = 'androidForWorkRestriction'
        macOS          = 'macOSRestriction'
    }
    $PersonalBlocked = [ordered]@{}
    foreach ($Platform in $PlatformMap.Keys) {
        $Value = $null
        if ($Restriction) {
            $Node = $Restriction.($PlatformMap[$Platform])
            if ($null -ne $Node -and $null -ne $Node.personalDeviceEnrollmentBlocked) { $Value = ($Node.personalDeviceEnrollmentBlocked -eq $true) }
        }
        $PersonalBlocked[$Platform] = $Value
    }
    $MdmDuringRegistrationDisabled = if ($MdmRead -and $MdmPolicy) { ($MdmPolicy.isMdmEnrollmentDuringRegistrationDisabled -eq $true) } else { $null }
    $MdmUserScope = if ($MdmRead -and $MdmPolicy) { [string]$MdmPolicy.appliesTo } else { $null }

    $EnrollmentLabels = @{
        userEnrollment                         = 'User enrollment (Company Portal or Access work or school)'
        windowsAutoEnrollment                  = 'Windows automatic enrollment (work account added)'
        windowsAzureADJoin                     = 'Entra join'
        windowsAzureADJoinUsingDeviceAuth      = 'Entra join (device authentication)'
        windowsBulkAzureDomainJoin             = 'Bulk Entra join (provisioning package)'
        windowsBulkUserless                    = 'Bulk enrollment (userless)'
        windowsCoManagement                    = 'Co-management (Configuration Manager)'
        azureAdJoinUsingAzureVmExtension       = 'Entra join (Azure VM extension)'
        deviceEnrollmentManager                = 'Device enrollment manager'
        appleUserEnrollment                    = 'Apple User Enrollment'
        appleUserEnrollmentWithServiceAccount  = 'Apple User Enrollment (service account)'
        appleBulkWithUser                      = 'Apple automated enrollment (with user)'
        appleBulkWithoutUser                   = 'Apple automated enrollment (no user)'
        androidEnterpriseFullyManaged          = 'Android Enterprise fully managed'
        androidEnterpriseDedicatedDevice       = 'Android Enterprise dedicated'
        androidEnterpriseCorporateWorkProfile  = 'Android Enterprise corporate work profile'
    }

    $Rows = foreach ($Device in $RawDevices) {
        if ([string]$Device.managedDeviceOwnerType -ne 'personal') { continue }
        $Enrolled = ConvertTo-UtcDate $Device.enrolledDateTime
        $Synced = ConvertTo-UtcDate $Device.lastSyncDateTime
        $EnrollType = [string]$Device.deviceEnrollmentType
        $Os = [string]$Device.operatingSystem
        [pscustomobject]@{
            Tenant                 = $TenantFilter
            id                     = [string]$Device.id
            deviceName             = [string]$Device.deviceName
            operatingSystem        = $Os
            osVersion              = [string]$Device.osVersion
            model                  = [string]$Device.model
            userPrincipalName      = [string]$Device.userPrincipalName
            userDisplayName        = [string]$Device.userDisplayName
            enrolledDateTime       = if ($Enrolled) { $Enrolled.ToString('o') } else { $null }
            lastSyncDateTime       = if ($Synced) { $Synced.ToString('o') } else { $null }
            daysSinceSync          = if ($Synced) { [int][math]::Floor(($Now - $Synced).TotalDays) } else { $null }
            deviceEnrollmentType   = $EnrollType
            enrollmentType         = if ($EnrollmentLabels.ContainsKey($EnrollType)) { $EnrollmentLabels[$EnrollType] } else { $EnrollType }
            joinType               = [string]$Device.joinType
            viaWorkAccount         = ($Os -eq 'Windows' -and [string]$Device.joinType -eq 'azureADRegistered')
            complianceState        = [string]$Device.complianceState
            managementState        = [string]$Device.managementState
            isNew                  = ($null -ne $Enrolled -and ($Now - $Enrolled).TotalDays -le $NewDays)
        }
    }
    $Rows = @($Rows)

    $OsCount = { param($Name) @($Rows | Where-Object { $_.operatingSystem -eq $Name }).Count }
    $Known = @('Windows', 'iOS', 'iPadOS', 'Android', 'macOS')
    $Summary = [pscustomobject]@{
        Tenant                                    = $TenantFilter
        PersonalDevices                           = $Rows.Count
        Windows                                   = & $OsCount 'Windows'
        iOS                                       = (& $OsCount 'iOS') + (& $OsCount 'iPadOS')
        Android                                   = & $OsCount 'Android'
        macOS                                     = & $OsCount 'macOS'
        Other                                     = @($Rows | Where-Object { $_.operatingSystem -notin $Known }).Count
        WindowsViaWorkAccount                     = @($Rows | Where-Object { $_.viaWorkAccount -eq $true }).Count
        NewDevices                                = @($Rows | Where-Object { $_.isNew -eq $true }).Count
        NonCompliant                              = @($Rows | Where-Object { $_.complianceState -eq 'noncompliant' }).Count
        PersonalBlockedWindows                    = $PersonalBlocked.Windows
        PersonalBlockediOS                        = $PersonalBlocked.iOS
        PersonalBlockedAndroid                    = $PersonalBlocked.Android
        PersonalBlockedAndroidForWork             = $PersonalBlocked.AndroidForWork
        PersonalBlockedmacOS                      = $PersonalBlocked.macOS
        DefaultRestrictionFound                   = if ($RestrictionRead) { [bool]$Restriction } else { $null }
        MdmEnrollmentDuringRegistrationDisabled   = $MdmDuringRegistrationDisabled
        MdmUserScope                              = $MdmUserScope
        CacheTimestamp                            = $CacheTimestamp
    }

    return [pscustomobject]@{
        Tenant  = $TenantFilter
        Source  = if ($FromCache) { 'cache' } else { 'live' }
        NewDays = $NewDays
        Tenants = @($Summary)
        Devices = $Rows
        Errors  = @($Errors)
    }
}
