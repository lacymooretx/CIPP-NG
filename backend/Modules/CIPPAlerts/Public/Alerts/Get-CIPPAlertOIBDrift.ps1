function Get-CIPPAlertOIBDrift {
    <#
    .SYNOPSIS
        Weekly OpenIntuneBaseline (OIB) version drift check
    .DESCRIPTION
        Runs Get-CIPPOIBDrift and raises the Outdated findings (a "Win - OIB -" policy older than the version
        in the latest OIB Windows release) and the Retired ones (deprecated in, or missing from, that release).
        Policies the tenant has not deployed are not alerted on: partial OIB adoption is normal. A tenant with no
        OIB policies produces nothing.
        State mode: a finding notifies once and resolves when the policy is updated or removed. Rows carry the
        finding Key as Id (State|policy id|version), so the lifecycle hash ignores message wording. A run where a
        policy collection could not be read does not report, because "could not check" is not "clear".
        Aspendora fork addition (Vikunja CIPP-20).
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
        $Report = Get-CIPPOIBDrift -TenantFilter $TenantFilter -ExcludeMissing
        if (@($Report.Errors).Count -gt 0) {
            # No OIB policy seen and reads failing is usually a tenant without Intune; stay quiet for it.
            if ($Report.OibItemCount -gt 0) {
                Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "OIB drift: skipped reporting, could not read everything: $(@($Report.Errors) -join '; ')" -sev Warning
            }
            return
        }
        $Rows = @($Report.Findings | Where-Object { $_.State -in @('Outdated', 'Retired') } | ForEach-Object {
                [pscustomobject]@{ State = $_.State; Policy = $_.Name; Type = $_.Type; CurrentVersion = $_.CurrentVersion; LatestVersion = $_.LatestVersion; LatestName = $_.LatestName; Release = $_.ReleaseTag; Message = $_.Message; Id = $_.Key }
            })
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "OIB drift check failed: $((Get-CippException -Exception $_).NormalizedError)" -sev Error -LogData (Get-CippException -Exception $_)
    }
}
