function Get-CIPPAlertPersonalDevices {
    <#
    .SYNOPSIS
        Alert on personally owned devices enrolled in Intune
    .DESCRIPTION
        Reads the tenant's personally owned managed devices live through Get-CIPPPersonalDevices and raises each one.
        State mode (Id = 'PersonalDevice|<managed device id>'): a device notifies once when it first appears and the
        alert clears when it is retired, deleted or changed to corporate. The message says how the device got in
        (a Windows device that is Entra registered was enrolled by adding a work account) and which control would have
        stopped it: the default platform restriction (personally owned devices blocked) and the "Disable MDM enrollment
        when adding work or school account" setting. Fields that change every sync (last sync, compliance) are left out
        so the content hash stays stable. Retired or wiped devices are skipped.
        PersonalDevicesComputersOnly limits the alert to Windows and macOS, for tenants that allow personal phones on
        purpose. Report only. Aspendora fork addition (Vikunja CIPP-21).
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        [Parameter(Mandatory)]
        $TenantFilter
    )
    $ComputersOnly = ConvertTo-CIPPBoolean $InputValue.PersonalDevicesComputersOnly
    try {
        $Report = Get-CIPPPersonalDevices -TenantFilter $TenantFilter
    } catch {
        # No trace on a failed read: an empty trace would clear every open personal-device alert.
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Personal devices: could not read managed devices: $((Get-CippException -Exception $_).NormalizedError)" -sev Warning
        return
    }
    $Summary = @($Report.Tenants)[0]
    $Rows = foreach ($Device in @($Report.Devices)) {
        if (-not (Test-CIPPManagedDeviceActive -Device $Device)) { continue }
        if ($ComputersOnly -eq $true -and $Device.operatingSystem -notin @('Windows', 'macOS')) { continue }
        $How = if ($Device.viaWorkAccount -eq $true) {
            'It is Entra registered, so it was most likely enrolled when the user added a work account in Settings > Accounts > Access work or school.'
        } else {
            "Enrollment type: $($Device.enrollmentType)."
        }
        $Fix = [System.Collections.Generic.List[string]]::new()
        if ($Device.operatingSystem -eq 'Windows') {
            if ($Summary.PersonalBlockedWindows -eq $false) { $Fix.Add('block personally owned Windows devices in the default platform restriction') }
            if ($Summary.MdmEnrollmentDuringRegistrationDisabled -eq $false) { $Fix.Add("turn on 'Disable MDM enrollment when adding work or school account on Windows'") }
        }
        [pscustomobject]@{
            Id             = "PersonalDevice|$($Device.id)"
            DeviceName     = $Device.deviceName
            User           = $Device.userPrincipalName
            OS             = $Device.operatingSystem
            EnrollmentType = $Device.deviceEnrollmentType
            JoinType       = $Device.joinType
            Enrolled       = $Device.enrolledDateTime
            ViaWorkAccount = $Device.viaWorkAccount
            Message        = "$($Device.deviceName) ($($Device.operatingSystem)) enrolled in Intune as a personally owned device for $($Device.userPrincipalName). $How" + $(if ($Fix.Count -gt 0) { " To stop new ones: $($Fix -join '; ')." } else { '' })
        }
    }
    Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows)
}
