function Invoke-CIPPTenantSweep {
    <#
    .SYNOPSIS
        Runs a per-tenant report for one tenant, or for every tenant the caller may see when TenantFilter is AllTenants.
    .DESCRIPTION
        AllTenants is narrowed to the caller's allowed tenants (Test-CIPPAccess -TenantList), the same rule the
        AnyTenant write endpoints use. Tenants run one after another inside a time budget (default 150 s, under
        the HTTP gateway timeout); tenants not reached are returned in Skipped instead of being silently dropped,
        and a tenant whose report throws is returned in Failed. Returns @{ Results; Failed; Skipped }.
        Aspendora fork addition (Vikunja CIPP-22 / CIPP-24).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Request,
        [Parameter(Mandatory)][string]$TenantFilter,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$BudgetSeconds = 150
    )

    if ($TenantFilter -ne 'AllTenants') {
        return [pscustomobject]@{ Results = @(& $ScriptBlock $TenantFilter); Failed = @(); Skipped = @() }
    }

    $Tenants = @(Get-Tenants)
    $Allowed = Test-CIPPAccess -Request $Request -TenantList
    if ($Allowed -ne 'AllTenants') { $Tenants = @($Tenants | Where-Object { $_.customerId -in @($Allowed) }) }

    $Clock = [System.Diagnostics.Stopwatch]::StartNew()
    $Results = [System.Collections.Generic.List[object]]::new()
    $Failed = [System.Collections.Generic.List[object]]::new()
    $Skipped = [System.Collections.Generic.List[string]]::new()
    foreach ($T in $Tenants) {
        $Name = [string]$T.defaultDomainName
        if ($Clock.Elapsed.TotalSeconds -ge $BudgetSeconds) { $Skipped.Add($Name); continue }
        try {
            foreach ($R in @(& $ScriptBlock $Name)) { $Results.Add($R) }
        } catch {
            $Failed.Add([pscustomobject]@{ Tenant = $Name; Error = (Get-CippException -Exception $_).NormalizedError })
        }
    }
    [pscustomobject]@{ Results = @($Results); Failed = @($Failed); Skipped = @($Skipped) }
}
