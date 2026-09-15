function Get-CIPPAlertPrinterDeployFailure {
    <#
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

    # Only alert on a failure that has had time to correct itself. Intune re-runs a platform
    # script on the device's next check-in, so a state that changed minutes ago may already be
    # on its way to succeeding. Ticketing that is exactly the non-actionable noise that flooded
    # ConnectWise before. Default: the failure must have stood for 24 hours.
    $MinimumHours = if ($InputValue.PrinterDeployFailureHours) { [int]$InputValue.PrinterDeployFailureHours } else { 24 }
    $Cutoff = (Get-Date).ToUniversalTime().AddHours(-$MinimumHours)

    try {
        $Scripts = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts' -tenantid $TenantFilter |
                Where-Object { $_.displayName -like 'CIPP: Printer - *' })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Printer deployment alert: unable to list printer scripts: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return
    }

    if ($Scripts.Count -eq 0) { return }

    $Failures = foreach ($Script in $Scripts) {
        $PrinterName = $Script.displayName -replace '^CIPP: Printer - ', ''
        try {
            $States = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($Script.id)/deviceRunStates?`$expand=managedDevice(`$select=deviceName)" -tenantid $TenantFilter)
        } catch {
            # A script whose states cannot be read is reported as a log entry, not as a device
            # failure - inventing a device-level failure would be worse than saying nothing.
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Printer deployment alert: unable to read run states for '$PrinterName'." -sev Info
            continue
        }

        foreach ($State in $States) {
            if ($State.runState -ne 'fail') { continue }

            $LastUpdate = $null
            if ($State.lastStateUpdateDateTime) { $LastUpdate = [datetime]$State.lastStateUpdateDateTime }
            # No timestamp means we cannot prove the failure is sustained, so hold off rather
            # than raise a ticket that might be minutes old.
            if (-not $LastUpdate -or $LastUpdate.ToUniversalTime() -gt $Cutoff) { continue }

            $HoursFailing = [math]::Round(((Get-Date).ToUniversalTime() - $LastUpdate.ToUniversalTime()).TotalHours)
            [PSCustomObject]@{
                Message      = "Printer '$PrinterName' has failed to install on $($State.managedDevice.deviceName) for $HoursFailing hours (error code $($State.errorCode))."
                Printer      = $PrinterName
                DeviceName   = $State.managedDevice.deviceName
                ErrorCode    = $State.errorCode
                HoursFailing = $HoursFailing
                Tenant       = $TenantFilter
            }
        }
    }

    if ($Failures) {
        Write-AlertTrace -cmdletName $MyInvocation.MyCommand -tenantFilter $TenantFilter -data $Failures
    }
}
