function Get-CIPPAlertConditionalAccessPlans {
    <#
    .SYNOPSIS
        Alert when a Conditional Access policy plan first appears in a tenant
    .DESCRIPTION
        Rules in a plan do not appear among the policies, so CIPP's posture, gap analysis, drift, templates and
        backups all miss them, and a client or vendor can create one at any time. State mode: each plan notifies
        once, stays quiet while it exists and resolves when deleted. The row Id is the plan id, so a new rule or
        a rename does not notify again. A failed read does not report, because "could not check" is not "clear".
        Report only. Aspendora fork addition (Vikunja CIPP-56).
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
        $Licensed = Test-CIPPStandardLicense -StandardName 'ConditionalAccessCache' -TenantFilter $TenantFilter -Preset Entra -SkipLog
        if ($Licensed -eq $false) { return }
        $Rows = @(Get-CIPPConditionalAccessPlans -TenantFilter $TenantFilter | ForEach-Object {
                [pscustomobject]@{
                    Id        = "Plan|$($_.id)"
                    Severity  = 'High'
                    Plan      = $_.displayName
                    RuleCount = $_.ruleCount
                    Message   = "Conditional Access plan '$($_.displayName)' exists in this tenant with $($_.ruleCount) rule(s). CIPP does not evaluate plans, so its posture, gap analysis and drift results may be wrong here, and plans are not backed up. Find out who created it, and check that its shared conditions exclude the break-glass group."
                }
            })
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Conditional Access plan check failed: $((Get-CippException -Exception $_).NormalizedError)" -sev Warning
    }
}
