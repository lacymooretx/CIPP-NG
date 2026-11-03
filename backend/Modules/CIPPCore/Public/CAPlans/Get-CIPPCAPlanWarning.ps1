function Get-CIPPCAPlanWarning {
    <#
    .SYNOPSIS
        The cached "plans CIPP does not evaluate" warning for a tenant, or $null.
    .DESCRIPTION
        Reads the ConditionalAccessPlans cache, collecting it on a miss. Never throws: a warning that cannot be
        worked out must not break the report it decorates. Aspendora fork addition (Vikunja CIPP-56).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    try {
        (Get-CIPPCAPlanSummary -Plans @(Get-CIPPSimulationCache -TenantFilter $TenantFilter -Type 'ConditionalAccessPlans')).Warning
    } catch {
        Write-Information "Get-CIPPCAPlanWarning: could not read cached plans for $TenantFilter - $($_.Exception.Message)"
    }
}
