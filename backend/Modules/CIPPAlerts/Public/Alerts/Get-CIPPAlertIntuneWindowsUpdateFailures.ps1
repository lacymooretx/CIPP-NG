function Get-CIPPAlertIntuneWindowsUpdateFailures {
    <#
    .SYNOPSIS
        Alert on Windows Update failures reported by Intune update profiles
    .DESCRIPTION
        Graph has no GET for per-device Windows Update state (windowsFeatureUpdateProfiles/{id}/deviceUpdateStates and
        the update-ring deviceUpdateStates segment both return "Resource not found", re-checked 2026-10-31). The
        working route is the Intune reports API, as ListIntuneDeploymentStatus Type=FeatureUpdates already does:
          - Feature update profiles -> POST reports/getWindowsUpdateAlertsPerPolicyPerDeviceReport with a
            mandatory (PolicyId eq '<id>') filter. Verified live (3endt.com, 2026-10-31).
          - Expedited quality update profiles -> reports/getWindowsQualityUpdateAlertsPerPolicyPerDeviceReport, and
            driver update profiles -> reports/getWindowsDriverUpdateAlertsPerPolicyPerDeviceReport. Same shape per
            Microsoft's reports API, NOT yet verified against a live tenant, so each is opt-in
            (WUFailuresIncludeQuality, WUFailuresIncludeDrivers).
        The reports need Windows diagnostic data enabled for Intune (the IntuneWindowsDiagnostic standard) and
        Windows E3/E5-equivalent licensing. One row per device and alert per profile.
        State mode: Id = 'WU|<family>|<profile id>|<device>|<alert>', so a failure notifies once and resolves when the
        report stops listing it. If any requested report could not be read the run does not report, because
        "could not check" is not "clear". Report only. Aspendora fork addition (Vikunja CIPP-27).
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
    $Families = [System.Collections.Generic.List[object]]::new()
    $Families.Add(@{ Name = 'FeatureUpdate'; List = 'windowsFeatureUpdateProfiles'; Report = 'getWindowsUpdateAlertsPerPolicyPerDeviceReport' })
    if ((ConvertTo-CIPPBoolean $InputValue.WUFailuresIncludeQuality) -eq $true) {
        $Families.Add(@{ Name = 'QualityUpdate'; List = 'windowsQualityUpdateProfiles'; Report = 'getWindowsQualityUpdateAlertsPerPolicyPerDeviceReport' })
    }
    if ((ConvertTo-CIPPBoolean $InputValue.WUFailuresIncludeDrivers) -eq $true) {
        $Families.Add(@{ Name = 'DriverUpdate'; List = 'windowsDriverUpdateProfiles'; Report = 'getWindowsDriverUpdateAlertsPerPolicyPerDeviceReport' })
    }

    # First non-empty value: report columns can be present but blank.
    $First = { foreach ($V in $args) { if (-not [string]::IsNullOrWhiteSpace([string]$V)) { return [string]$V } }; '' }
    $Rows = [System.Collections.Generic.List[object]]::new()
    foreach ($F in $Families) {
        try {
            $Profiles = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/$($F.List)?`$select=id,displayName" -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id })
        } catch {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Windows Update failures: could not list $($F.List): $((Get-CippException -Exception $_).NormalizedError). Skipped reporting this run." -sev Warning
            return
        }
        foreach ($P in $Profiles) {
            try {
                $Body = @{ filter = "(PolicyId eq '$($P.id)')"; top = 500 } | ConvertTo-Json -Compress
                $Report = New-GraphPOSTRequest -uri "https://graph.microsoft.com/beta/deviceManagement/reports/$($F.Report)" -tenantid $TenantFilter -type POST -body $Body
            } catch {
                Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Windows Update failures: $($F.Report) failed for '$($P.displayName)': $((Get-CippException -Exception $_).NormalizedError). Skipped reporting this run." -sev Warning
                return
            }
            foreach ($R in @(ConvertFrom-CIPPIntuneReportTable -Report $Report)) {
                $Device = & $First $R.IntuneDeviceId $R.DeviceId $R.AADDeviceId $R.AzureADDeviceId $R.DeviceName
                $AlertCode = & $First $R.AlertMessage $R.AlertType $R.AlertMessage_loc
                # The _loc columns carry readable text; the bare ones are ids.
                $Alert = & $First $R.AlertMessage_loc $R.AlertMessage
                $Detail = & $First $R.AlertMessageDescription_loc $R.AlertMessageDescription
                $Rows.Add([pscustomobject]@{
                        Id         = "WU|$($F.Name)|$($P.id)|$Device|$AlertCode"
                        Family     = $F.Name
                        Profile    = [string]$P.displayName
                        DeviceName = [string]$R.DeviceName
                        User       = [string]$R.UPN
                        Alert      = $Alert
                        Detail     = $Detail
                        Message    = "$($R.DeviceName): $Alert$(if ($Detail) { " - $Detail" }) ($($F.Name) profile '$($P.displayName)')."
                    })
            }
        }
    }
    Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows)
}
