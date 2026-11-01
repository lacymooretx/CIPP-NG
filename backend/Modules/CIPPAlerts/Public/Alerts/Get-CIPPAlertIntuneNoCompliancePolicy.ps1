function Get-CIPPAlertIntuneNoCompliancePolicy {
    <#
    .SYNOPSIS
        Alert on Intune devices that have no compliance policy assigned
    .DESCRIPTION
        Intune's built-in Default Device Compliance Policy evaluates "Has a compliance policy assigned" on every
        device. Its per-device states (beta deviceCompliancePolicySettingStateSummaries/
        DefaultDeviceCompliancePolicy.RequireDeviceCompliancePolicyAssigned/deviceComplianceSettingStates, verified
        2026-10-31) are read and every device not in state compliant is raised: nonCompliant means no compliance
        policy targets it, error / conflict mean Intune could not evaluate it (only raised when
        NoComplianceIncludeErrors is on). The device's compliance therefore depends only on the tenant's "Mark devices
        with no compliance policy assigned as" setting, which is usually Compliant and lets it through Conditional
        Access unchecked. DeviceCompliance (non-compliant devices) is a different signal and is not duplicated.
        Devices enrolled within NoComplianceGraceDays (default 1) and retired / wiped devices are skipped.
        State mode: Id = 'NoCompliance|<managed device id>'. Report only. Aspendora fork addition (Vikunja CIPP-27).
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
    $GraceDays = 1
    $Parsed = 0
    if ($null -ne $InputValue.NoComplianceGraceDays -and [int]::TryParse([string]$InputValue.NoComplianceGraceDays, [ref]$Parsed) -and $Parsed -ge 0) { $GraceDays = $Parsed }
    $IncludeErrors = ConvertTo-CIPPBoolean $InputValue.NoComplianceIncludeErrors
    $States = @('nonCompliant')
    if ($IncludeErrors -eq $true) { $States += @('error', 'conflict') }
    $Cutoff = [datetime]::UtcNow.AddDays(-$GraceDays)
    try {
        $Settings = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicySettingStateSummaries/DefaultDeviceCompliancePolicy.RequireDeviceCompliancePolicyAssigned/deviceComplianceSettingStates' -tenantid $TenantFilter -ErrorAction Stop)
        $Devices = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,userPrincipalName,enrolledDateTime,managementState,complianceState&$top=999' -tenantid $TenantFilter -ErrorAction Stop)
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Intune compliance coverage: could not read device states: $((Get-CippException -Exception $_).NormalizedError)" -sev Warning
        return
    }
    $ById = @{}
    foreach ($D in $Devices) { if ($D.id) { $ById[[string]$D.id] = $D } }
    # Intune keeps one row per context: a device/system row (no user) plus one per user who signed in. With a
    # compliance policy assigned to users, the system row stays nonCompliant while each user row is compliant, so a
    # device is only uncovered when NO row is compliant (2026-11-01: IAN-PC and the Cloud PCs were false positives).
    $Uncovered = foreach ($Group in @($Settings | Group-Object -Property deviceId)) {
        if (@($Group.Group | Where-Object { [string]$_.state -eq 'compliant' }).Count -gt 0) { continue }
        $Group.Group | Where-Object { [string]$_.state -in $States } | Select-Object -First 1
    }
    $Rows = foreach ($S in @($Uncovered | Where-Object { $_ })) {
        $Device = $ById[[string]$S.deviceId]
        # Not in the managed device list = gone or retired since the summary was computed.
        if (-not $Device -or -not (Test-CIPPManagedDeviceActive -Device $Device)) { continue }
        $Enrolled = if ($Device.enrolledDateTime -is [datetime]) { ([datetime]$Device.enrolledDateTime).ToUniversalTime() } elseif ($Device.enrolledDateTime) { ([datetimeoffset]$Device.enrolledDateTime).UtcDateTime } else { [datetime]::MinValue }
        if ($Enrolled -gt $Cutoff) { continue }
        $NoPolicy = [string]$S.state -eq 'nonCompliant'
        [pscustomobject]@{
            Id              = "NoCompliance|$($S.deviceId)"
            DeviceName      = [string]$Device.deviceName
            User            = [string]$Device.userPrincipalName
            OS              = [string]$Device.operatingSystem
            State           = [string]$S.state
            ComplianceState = [string]$Device.complianceState
            Message         = if ($NoPolicy) {
                "$($Device.deviceName) ($($Device.operatingSystem)) has no compliance policy assigned. Its compliance comes only from the tenant default, so Conditional Access cannot rely on it; assign a compliance policy for $($Device.operatingSystem)."
            } else {
                "Intune could not evaluate whether $($Device.deviceName) has a compliance policy assigned (state $($S.state))."
            }
        }
    }
    Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows)
}
