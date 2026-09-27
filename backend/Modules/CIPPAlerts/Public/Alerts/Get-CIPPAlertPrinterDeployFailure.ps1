function Get-CIPPAlertPrinterDeployFailure {
    <#
    .SYNOPSIS
        Alert on CIPP printer deployments that have been failing on a device for a sustained period.
    .DESCRIPTION
        Dedup is the AlertLifecycle (CIPP 11.0), keyed on printer + device (the item's Id). The
        Message carries "failing for N hours", which changes every run; without a stable Id it would
        be the hash key and every run would notify again. Each successful run reconciles the full
        set, so a device that starts succeeding resolves, and it notifies again if it fails again.
        When a script's run states cannot be read, the run appends instead of resolving what it
        could not see. The first reconcile after the upgrade seeds the failures it finds silently -
        the pre-lifecycle trace re-alerted them daily, so they are already known.
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

    $Partial = $false
    $Failures = @(foreach ($Script in $Scripts) {
        $PrinterName = $Script.displayName -replace '^CIPP: Printer - ', ''
        try {
            $States = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($Script.id)/deviceRunStates?`$expand=managedDevice(`$select=deviceName)" -tenantid $TenantFilter)
        } catch {
            # A script whose states cannot be read is reported as a log entry, not as a device
            # failure - inventing a device-level failure would be worse than saying nothing.
            $Partial = $true
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
                # Lifecycle identity (Get-AlertContentHash keys on Id before Message).
                Id           = "$PrinterName|$($State.managedDevice.deviceName)"
                Message      = "Printer '$PrinterName' has failed to install on $($State.managedDevice.deviceName) for $HoursFailing hours (error code $($State.errorCode))."
                Printer      = $PrinterName
                DeviceName   = $State.managedDevice.deviceName
                ErrorCode    = $State.errorCode
                HoursFailing = $HoursFailing
                Tenant       = $TenantFilter
            }
        }
    })

    $CmdletName = [string]$MyInvocation.MyCommand
    Initialize-CIPPAlertLifecycleBaseline -CmdletName $CmdletName -TenantFilter $TenantFilter `
        -BaselinePartition 'PrinterDeployFailureLifecycle' -CurrentItems $Failures `
        -KnownItemsFromBaseline { param($Ids) }

    # Reconcile every successful run, including an empty one, so fixed devices resolve.
    Write-AlertTrace -cmdletName $CmdletName -tenantFilter $TenantFilter -data $Failures -Append:$Partial
}
