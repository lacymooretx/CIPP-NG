function Get-CIPPAlertDriverUpdatesBlocked {
    <#
    .SYNOPSIS
        Alert when update rings or Settings Catalog policies block Windows Update drivers
    .DESCRIPTION
        Runs Get-CIPPDriverBlockingPolicies: update rings with driversExcluded = true and Settings Catalog policies
        setting "Exclude WU Drivers In Quality Update" to Exclude. Either one stops devices from getting drivers and
        firmware, whatever the driver update profile says. Unassigned policies are raised only when
        DriverBlockIncludeUnassigned is on. If either policy family could not be read the run does not report.
        State mode: Id = 'Ring|<id>' / 'Catalog|<id>'. Report only. Aspendora fork addition (Vikunja CIPP-24).
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
    try {
        $IncludeUnassigned = ConvertTo-CIPPBoolean $InputValue.DriverBlockIncludeUnassigned
        $Result = Get-CIPPDriverBlockingPolicies -TenantFilter $TenantFilter
        if (@($Result.Errors).Count -gt 0) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Driver updates blocked: skipped reporting, could not read everything: $(@($Result.Errors) -join '; ')" -sev Warning
            return
        }
        $Rows = @($Result.Findings | Where-Object { $_.Assigned -eq $true -or $IncludeUnassigned -eq $true } | ForEach-Object {
                [pscustomobject]@{ Id = $_.Id; Kind = $_.Kind; Policy = $_.PolicyName; Assignments = $_.AssignmentCount; Message = $_.Message }
            })
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Driver updates blocked check failed: $((Get-CippException -Exception $_).NormalizedError)" -sev Error -LogData (Get-CippException -Exception $_)
    }
}
