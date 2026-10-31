function Get-CIPPIntuneEffectivePolicy {
    <#
    .SYNOPSIS
        Effective Intune policy for one device: what lands on it, through which assignment, and what Intune reports.
    .DESCRIPTION
        Read-only. Collects from Graph and evaluates with Resolve-CIPPIntuneAssignments:
          1. The managedDevice (by Intune id, or by azureADDeviceId), the Entra device object (by deviceId, or by
             object id when the device is not Intune-managed) and its transitiveMemberOf groups.
          2. The primary user (managedDevice.userId) and the user's transitiveMemberOf groups.
          3. The Autopilot group tag, from physicalIds [OrderId] and the Autopilot identity, because dynamic groups
             are often built on it. Shown for context; group membership is read, not re-derived.
          4. Every policy family with its assignments (Get-CIPPIntuneAssignablePolicies), assigned apps included,
             and the assignment filters.
          5. Best-effort device status: deviceConfigurationStates (device configuration profiles) and
             deviceCompliancePolicyStates. Settings Catalog / endpoint security policies have no per-device state in
             these collections, so their DeviceStatus is blank rather than guessed.
          6. Settings overlap: /configurationPolicies/{id}/settings for applicable Settings Catalog policies only,
             fed to Find-CIPPIntuneSettingOverlap.
        Returns @{ Device; Results; Overlaps; Summary; Errors; Notes }. Aspendora fork addition (Vikunja CIPP-19).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [Parameter(Mandatory)][string]$DeviceId
    )

    $Guid = [guid]::Empty
    if (-not [guid]::TryParse($DeviceId, [ref]$Guid)) { throw 'DeviceId must be an Intune managed device id or an Entra device id (a GUID).' }
    $DeviceId = $Guid.ToString()

    $Errors = [System.Collections.Generic.List[string]]::new()
    $Notes = [System.Collections.Generic.List[string]]::new()
    $Beta = 'https://graph.microsoft.com/beta'
    $Get = { param($Uri) New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -ErrorAction Stop }
    $Msg = { param($E) (Get-CippException -Exception $E).NormalizedError }
    $ManagedSelect = 'id,deviceName,azureADDeviceId,operatingSystem,osVersion,manufacturer,model,serialNumber,userId,userPrincipalName,enrollmentProfileName,managedDeviceOwnerType,deviceCategoryDisplayName,complianceState,lastSyncDateTime'

    # --- 1. Device ----------------------------------------------------------------------------------
    $Managed = $null
    try { $Managed = & $Get "$Beta/deviceManagement/managedDevices/$DeviceId`?`$select=$ManagedSelect" } catch {}
    if (-not $Managed) {
        try { $Managed = @(& $Get "$Beta/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$DeviceId'&`$select=$ManagedSelect") | Select-Object -First 1 } catch {}
    }
    $Entra = $null
    $EntraSelect = 'id,deviceId,displayName,operatingSystem,operatingSystemVersion,physicalIds,manufacturer,model,trustType'
    $LookupDeviceId = if ($Managed.azureADDeviceId -and $Managed.azureADDeviceId -ne '00000000-0000-0000-0000-000000000000') { $Managed.azureADDeviceId } else { $DeviceId }
    try { $Entra = @(& $Get "$Beta/devices?`$filter=deviceId eq '$LookupDeviceId'&`$select=$EntraSelect") | Select-Object -First 1 } catch { $Errors.Add("Entra device lookup: $(& $Msg $_)") }
    if (-not $Entra -and -not $Managed) {
        try { $Entra = & $Get "$Beta/devices/$DeviceId`?`$select=$EntraSelect" } catch {}
    }
    if (-not $Managed -and $Entra.deviceId -and $Entra.deviceId -ne $DeviceId) {
        # Given the Entra object id: find the Intune record through the Entra deviceId.
        try { $Managed = @(& $Get "$Beta/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$($Entra.deviceId)'&`$select=$ManagedSelect") | Select-Object -First 1 } catch {}
    }
    if (-not $Managed -and -not $Entra) { throw "No Intune managed device or Entra device with id $DeviceId was found in $TenantFilter." }
    if (-not $Managed) { $Notes.Add('The device is not Intune-managed (no managedDevice record), so Intune policies will not apply until it enrols. Showing what would target it.') }
    if (-not $Entra) { $Errors.Add('No Entra device object was found for this device, so device group membership is unknown and device-group assignments cannot be matched.') }

    $DeviceGroups = @()
    $GroupNames = @{}
    if ($Entra.id) {
        try {
            $DeviceGroups = @(& $Get "$Beta/devices/$($Entra.id)/transitiveMemberOf?`$select=id,displayName" | Where-Object { $_.'@odata.type' -in @($null, '#microsoft.graph.group') -and $_.id })
            foreach ($G in $DeviceGroups) { $GroupNames[[string]$G.id] = [string]$G.displayName }
        } catch { $Errors.Add("Device group membership: $(& $Msg $_)") }
    }

    # --- 2. Primary user ----------------------------------------------------------------------------
    $UserGroups = @()
    $UserName = $Managed.userPrincipalName
    $UserId = $Managed.userId
    $HasUser = [bool]($UserId -and $UserId -ne '00000000-0000-0000-0000-000000000000')
    if ($HasUser) {
        try {
            $UserGroups = @(& $Get "$Beta/users/$UserId/transitiveMemberOf?`$select=id,displayName" | Where-Object { $_.'@odata.type' -in @($null, '#microsoft.graph.group') -and $_.id })
            foreach ($G in $UserGroups) { $GroupNames[[string]$G.id] = [string]$G.displayName }
        } catch { $Errors.Add("Primary user group membership: $(& $Msg $_)") }
    } else {
        $Notes.Add('The device has no primary user (userless / shared / kiosk), so user-targeted assignments (All Users, user groups) do not apply.')
    }

    # --- 3. Autopilot group tag ---------------------------------------------------------------------
    $OrderIdTag = @($Entra.physicalIds | Where-Object { $_ -match '^\[OrderId\]:' } | ForEach-Object { $_ -replace '^\[OrderId\]:', '' }) | Select-Object -First 1
    $AutopilotTag = $null
    if ($Managed.serialNumber -and $Managed.serialNumber -match '^[A-Za-z0-9\-_. ]+$') {
        try {
            # $select on this collection returns HTTP 500 (seen 2026-10-31), so read the whole record.
            $Ap = @(& $Get "$Beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($Managed.serialNumber)')") | Where-Object { $_.serialNumber -eq $Managed.serialNumber } | Select-Object -First 1
            $AutopilotTag = $Ap.groupTag
        } catch { $Notes.Add("Autopilot record could not be read ($(& $Msg $_)); the group tag shown comes from the Entra device only.") }
    }

    # --- 4. Policies --------------------------------------------------------------------------------
    $Os = $Managed.operatingSystem ?? $Entra.operatingSystem
    $Platform = Get-CIPPIntunePolicyPlatform -OperatingSystem ([string]$Os)
    if (-not $Platform) { $Notes.Add("Device OS '$Os' is not recognised, so no policy was skipped on platform grounds.") }

    $Collected = Get-CIPPIntuneAssignablePolicies -TenantFilter $TenantFilter -IncludeApps
    foreach ($E in $Collected.Errors) { $Errors.Add($E) }

    $Ownership = switch ([string]$Managed.managedDeviceOwnerType) { 'company' { 'Corporate' } 'personal' { 'Personal' } default { $null } }
    $DeviceProperties = @{
        deviceName            = $Managed.deviceName ?? $Entra.displayName
        manufacturer          = $Managed.manufacturer ?? $Entra.manufacturer
        model                 = $Managed.model ?? $Entra.model
        osVersion             = $Managed.osVersion ?? $Entra.operatingSystemVersion
        enrollmentProfileName = $Managed.enrollmentProfileName
        deviceOwnership       = $Ownership
        deviceCategory        = $Managed.deviceCategoryDisplayName
    }

    $Resolved = Resolve-CIPPIntuneAssignments -Policies $Collected.Policies -DevicePlatform $Platform -DeviceProperties $DeviceProperties `
        -DeviceGroupIds @($DeviceGroups.id) -UserGroupIds @($UserGroups.id) -HasUser $HasUser -UserName $UserName -GroupNames $GroupNames -Filters $Collected.Filters
    $Rows = @($Resolved.Rows)

    # --- 5. Device status (best effort) -------------------------------------------------------------
    $StatusById = @{}
    if ($Managed.id) {
        $Rank = @{ error = 0; conflict = 1; nonCompliant = 2; notApplicable = 5; compliant = 4; remediated = 4; unknown = 6 }
        foreach ($C in @('deviceConfigurationStates', 'deviceCompliancePolicyStates')) {
            try {
                foreach ($S in @(& $Get "$Beta/deviceManagement/managedDevices/$($Managed.id)/$C`?`$select=id,displayName,state")) {
                    if (-not $S.id) { continue }
                    # One entry per user/system context; keep the worst.
                    $Old = $StatusById[[string]$S.id]
                    if (-not $Old -or ($Rank[[string]$S.state] ?? 3) -lt ($Rank[$Old] ?? 3)) { $StatusById[[string]$S.id] = [string]$S.state }
                }
            } catch { $Notes.Add("Device status ($C) could not be read: $(& $Msg $_)") }
        }
    }
    foreach ($R in $Rows) { $R | Add-Member -NotePropertyName DeviceStatus -NotePropertyValue ([string]$StatusById[$R.PolicyId]) -Force }

    # --- 6. Settings Catalog overlap ----------------------------------------------------------------
    $Overlaps = @()
    $Catalog = @($Rows | Where-Object { $_.Family -eq 'ConfigurationPolicies' -and $_.Status -in @('Applies', 'Applies unless filter excludes (not evaluated)') })
    if ($Catalog.Count -gt 1) {
        $Requests = @($Catalog | ForEach-Object { [pscustomobject]@{ id = "s-$($_.PolicyId)"; method = 'GET'; url = "/deviceManagement/configurationPolicies/$($_.PolicyId)/settings?`$top=1000" } })
        try {
            $SettingResults = @(New-GraphBulkRequest -Requests $Requests -tenantid $TenantFilter)
            $SettingsInput = foreach ($C in $Catalog) {
                $R = $SettingResults | Where-Object { $_.id -eq "s-$($C.PolicyId)" } | Select-Object -First 1
                if (-not $R -or ($null -ne $R.status -and ($R.status -lt 200 -or $R.status -ge 300))) { $Errors.Add("Settings for '$($C.PolicyName)' could not be read, so it is left out of the overlap check."); continue }
                [pscustomobject]@{ PolicyId = $C.PolicyId; PolicyName = $C.PolicyName; Settings = @($R.body.value) }
            }
            $Overlaps = @(Find-CIPPIntuneSettingOverlap -PolicySettings @($SettingsInput))
        } catch { $Errors.Add("Settings overlap check: $(& $Msg $_)") }
    }

    $Notes.Add('Assignment filters are evaluated only for device properties CIPP reads (deviceName, manufacturer, model, operatingSystemVersion, enrollmentProfileName, deviceOwnership, deviceCategory) and only for the -eq/-ne/-in/-notIn/-startsWith/-endsWith/-contains (and version -gt/-ge/-lt/-le) operators. Anything else is shown as "not evaluated" rather than guessed.')

    [pscustomobject]@{
        Device   = [pscustomobject]@{
            ManagedDeviceId   = $Managed.id
            EntraObjectId     = $Entra.id
            EntraDeviceId     = $Entra.deviceId ?? $Managed.azureADDeviceId
            DeviceName        = $DeviceProperties.deviceName
            OperatingSystem   = $Os
            OsVersion         = $DeviceProperties.osVersion
            Platform          = $Platform
            Manufacturer      = $DeviceProperties.manufacturer
            Model             = $DeviceProperties.model
            SerialNumber      = $Managed.serialNumber
            Ownership         = $Ownership
            EnrollmentProfile = $Managed.enrollmentProfileName
            PrimaryUser       = $UserName
            ComplianceState   = $Managed.complianceState
            LastSync          = $Managed.lastSyncDateTime
            GroupTag          = $AutopilotTag ?? $OrderIdTag
            DeviceGroups      = @($DeviceGroups | ForEach-Object { $_.displayName } | Sort-Object)
            UserGroupCount    = @($UserGroups).Count
        }
        Results  = $Rows
        Overlaps = $Overlaps
        Summary  = [pscustomobject]@{
            Applies         = @($Rows | Where-Object Status -EQ 'Applies').Count
            FilterUnknown   = @($Rows | Where-Object Status -EQ 'Applies unless filter excludes (not evaluated)').Count
            Excluded        = @($Rows | Where-Object Status -EQ 'Excluded').Count
            FilteredOut     = @($Rows | Where-Object Status -EQ 'Filtered out').Count
            PlatformSkipped = $Resolved.PlatformSkipped
            PoliciesRead    = @($Collected.Policies).Count
            Conflicts       = @($Overlaps | Where-Object Severity -EQ 'Conflict').Count
            Overlaps        = @($Overlaps | Where-Object Severity -EQ 'Overlap').Count
        }
        Errors   = @($Errors)
        Notes    = @($Notes)
    }
}
