function Get-CIPPAlertBreakGlassPosture {
    <#
    .SYNOPSIS
        Weekly break-glass (emergency access) posture check
    .DESCRIPTION
        Runs Get-CIPPBreakGlassPosture and raises its Error and Warning findings: no or only one break-glass account,
        not permanent Global Admin, subject to a Conditional Access policy, expiring password, no FIDO2 or
        person-bound MFA, untested for 90 days, other accounts with broad CA exclusions, Conditional Access plans it
        cannot evaluate, members of the exclusion group that are not registered, and restricted management AU issues.
        State mode: a finding notifies once and resolves when it is fixed. A run with collection errors does not
        report, because "could not check" is not "clear". Aspendora fork addition (Vikunja CIPP-4).
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
        $Report = Get-CIPPBreakGlassPosture -TenantFilter $TenantFilter
        if (@($Report.Errors).Count -gt 0) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Break-glass posture: skipped reporting, could not read everything: $(@($Report.Errors) -join '; ')" -sev Warning
            return
        }
        $Rows = @($Report.Findings | Where-Object { $_.Severity -in @('Error', 'Warning') } | ForEach-Object {
                [pscustomobject]@{ Severity = $_.Severity; Check = $_.Check; Account = $_.Account; Message = $_.Message; Fix = $_.Fix; Key = $_.Key; Id = $_.Key }
            })
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Break-glass posture check failed: $((Get-CippException -Exception $_).NormalizedError)" -sev Error -LogData (Get-CippException -Exception $_)
    }
}
