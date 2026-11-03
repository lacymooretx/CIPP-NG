function Resolve-CIPPManagedDevice {
    <#
    .SYNOPSIS
        Resolves an Intune managed device id, Entra deviceId or serial number to one Intune managed device.
    .DESCRIPTION
        Read-only. A miss and a failure are different answers, so each stays distinct:
          Found (200), Invalid (400), NotFound (404), Ambiguous (409, with Candidates).
        A Graph failure on a collection lookup throws; the caller reports it as an error, never as "not found".

        A GUID is tried as azureADDeviceId first because the $filter answers cleanly (empty or an error). Reading
        managedDevices/{id} for an unknown id returned an opaque "An error has occurred" rather than a 404
        (verified 2026-11-03), and $filter=id eq '...' is rejected outright. So a failed by-id read after a
        successful filter is reported as NotFound with Graph's text in Detail.

        Serials can repeat: OEM placeholders such as "Defaultstring" exist in real fleets, and
        re-enrolment can leave two records. More than one match is Ambiguous, never the first row.
        Aspendora fork addition (CIPP and ControlR integration).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [string]$TenantFilter,
        [string]$DeviceId,
        [string]$SerialNumber
    )

    $Result = {
        param($Status, $HttpStatus, $Message, $Device, $Candidates, $Detail)
        [pscustomobject]@{ Status = $Status; HttpStatus = [int]$HttpStatus; Message = $Message; Device = $Device; Candidates = @($Candidates | Where-Object { $_ }); Detail = $Detail }
    }

    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return (& $Result 'Invalid' 400 'tenantFilter is required and must name a single tenant.')
    }
    if (-not $DeviceId -and -not $SerialNumber) {
        return (& $Result 'Invalid' 400 'DeviceId (an Intune managed device id or an Entra deviceId) or SerialNumber is required.')
    }

    $Beta = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices'
    $Select = 'id,deviceName,azureADDeviceId,serialNumber,operatingSystem,osVersion,userId,userPrincipalName,complianceState,complianceGracePeriodExpirationDateTime,lastSyncDateTime'

    $Shape = {
        param($Row, $MatchedBy)
        [pscustomobject]@{
            ManagedDeviceId                 = [string]$Row.id
            EntraDeviceId                   = [string]$Row.azureADDeviceId
            DeviceName                      = [string]$Row.deviceName
            SerialNumber                    = [string]$Row.serialNumber
            OperatingSystem                 = [string]$Row.operatingSystem
            OsVersion                       = [string]$Row.osVersion
            PrimaryUser                     = [string]$Row.userPrincipalName
            ComplianceState                 = [string]$Row.complianceState
            ComplianceGracePeriodExpiration = $Row.complianceGracePeriodExpirationDateTime
            LastSync                        = $Row.lastSyncDateTime
            MatchedBy                       = $MatchedBy
        }
    }
    $Rows = {
        param($Filter)
        @(New-GraphGetRequest -uri "$Beta`?`$filter=$Filter&`$select=$Select" -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id })
    }
    $Pick = {
        param($Matches_, $MatchedBy, $Key)
        if ($Matches_.Count -eq 1) { return (& $Result 'Found' 200 $null (& $Shape $Matches_[0] $MatchedBy)) }
        $Candidates = @($Matches_ | Sort-Object lastSyncDateTime -Descending | ForEach-Object { & $Shape $_ $MatchedBy })
        & $Result 'Ambiguous' 409 "$($Matches_.Count) managed devices match $MatchedBy '$Key'. Retry with DeviceId set to the ManagedDeviceId of one of the Candidates." $null $Candidates
    }

    if ($DeviceId) {
        $Guid = [guid]::Empty
        if (-not [guid]::TryParse($DeviceId, [ref]$Guid)) {
            return (& $Result 'Invalid' 400 'DeviceId must be a GUID: an Intune managed device id or an Entra deviceId. Use SerialNumber for a serial.')
        }
        if ($Guid -eq [guid]::Empty) {
            return (& $Result 'Invalid' 400 'DeviceId is the empty GUID, which Intune uses for devices with no Entra device.')
        }
        $Id = $Guid.ToString()
        $ByEntra = @(& $Rows "azureADDeviceId eq '$Id'")
        if ($ByEntra.Count -gt 0) { return (& $Pick $ByEntra 'EntraDeviceId' $Id) }

        $Detail = $null
        try {
            $Row = New-GraphGetRequest -uri "$Beta/$Id`?`$select=$Select" -tenantid $TenantFilter -ErrorAction Stop
            if ($Row.id) { return (& $Result 'Found' 200 $null (& $Shape $Row 'ManagedDeviceId')) }
        } catch {
            $Detail = $_.Exception.Message
        }
        return (& $Result 'NotFound' 404 "No Intune managed device with id or Entra deviceId $Id was found in $TenantFilter." $null $null $Detail)
    }

    $Serial = $SerialNumber.Trim()
    $SafeSerial = [uri]::EscapeDataString((ConvertTo-CIPPODataFilterValue -Value $Serial -Type String))
    $BySerial = @(& $Rows "serialNumber eq '$SafeSerial'")
    if ($BySerial.Count -eq 0) {
        return (& $Result 'NotFound' 404 "No Intune managed device with serial number '$Serial' was found in $TenantFilter.")
    }
    return (& $Pick $BySerial 'SerialNumber' $Serial)
}
