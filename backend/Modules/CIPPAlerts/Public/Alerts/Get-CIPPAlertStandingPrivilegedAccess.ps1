function Get-CIPPAlertStandingPrivilegedAccess {
    <#
    .SYNOPSIS
        Weekly check of standing and excess directory privilege
    .DESCRIPTION
        Runs Get-CIPPRoleAssignmentReport and raises its Error and Warning findings: permanent Global Administrators
        other than registered break-glass accounts (with a least-privilege suggestion), non-Microsoft service
        principals holding Global Administrator or other privileged roles, guests holding privileged roles,
        privileged accounts with no successful sign-in for InactiveDays (default 45), and GDAP relationships with
        the customer that carry Global Administrator.
        Inputs: StandingAccessInactiveDays (number), StandingAccessAllowedApps (comma-separated appIds or app names,
        * wildcards, custom variables allowed): allow-listed service principals are not alerted on.
        State mode: one row per principal or relationship with a stable Id, so each notifies once and resolves when
        fixed. A run with collection errors does not report. Report only: nothing in the tenant is changed.
        Aspendora fork addition (Vikunja CIPP-15).
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
        $InactiveDays = 45
        $Parsed = 0
        if ($null -ne $InputValue.StandingAccessInactiveDays -and [int]::TryParse([string]$InputValue.StandingAccessInactiveDays, [ref]$Parsed) -and $Parsed -gt 0) { $InactiveDays = $Parsed }
        $AllowRaw = Get-CIPPTextReplacement -TenantFilter $TenantFilter -Text ([string]$InputValue.StandingAccessAllowedApps)
        $Allowed = @(([string]$AllowRaw) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

        $Report = Get-CIPPRoleAssignmentReport -TenantFilter $TenantFilter -InactiveDays $InactiveDays -AllowedServicePrincipals $Allowed
        if (@($Report.Errors).Count -gt 0 -or -not $Report.Summary) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Standing privileged access: skipped reporting, could not read everything: $(@($Report.Errors) -join '; ')" -sev Warning
            return
        }
        # Account, not UserPrincipalName: the lifecycle hashes UserPrincipalName before Id.
        $Rows = @($Report.Findings | Where-Object { $_.Severity -in @('Error', 'Warning') } | ForEach-Object {
                [pscustomobject]@{ Id = $_.Key; Severity = $_.Severity; Check = $_.Check; Account = $_.Account; Message = $_.Message; Fix = $_.Fix }
            })
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Standing privileged access check failed: $((Get-CippException -Exception $_).NormalizedError)" -sev Error -LogData (Get-CippException -Exception $_)
    }
}
