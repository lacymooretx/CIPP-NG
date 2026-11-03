function Save-CIPPEntraEntitlementSummary {
    <#
    .SYNOPSIS
        Stores the latest Entra ID P1/P2 entitlement summary for a tenant.
    .DESCRIPTION
        Table EntraEntitlement, PartitionKey 'Summary', RowKey = tenant. Written after a complete collection by
        ListEntraEntitlement and the EntraEntitlementGap alert. Read by the AllTenants view and by the CIPP test, which
        only reads stored data. This is CIPP's own table: nothing in the tenant is changed.
        Aspendora fork addition (Vikunja CIPP-47).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [Parameter(Mandatory)]$Report
    )
    if (-not $Report.Summary -or @($Report.Errors).Count -gt 0) { return }
    try {
        $Table = Get-CIPPTable -tablename 'EntraEntitlement'
        $S = $Report.Summary
        Add-CIPPAzDataTableEntity @Table -Force -Entity @{
            PartitionKey            = 'Summary'
            RowKey                  = [string]$TenantFilter
            Tenant                  = [string]$TenantFilter
            CheckedUtc              = [datetime]::UtcNow.ToString('o')
            CoveredP1               = [bool]$S.CoveredP1
            CoveredP2               = [bool]$S.CoveredP2
            P1Pool                  = [int]$S.P1Pool
            P2Pool                  = [int]$S.P2Pool
            P1InScope               = [int]$S.P1InScope
            P2InScope               = [int]$S.P2InScope
            P1Shortfall             = [int]$S.P1Shortfall
            P2Shortfall             = [int]$S.P2Shortfall
            P1ActiveShortfall       = [int]$S.P1ActiveShortfall
            P2ActiveShortfall       = [int]$S.P2ActiveShortfall
            P1InactiveInScope       = [int]$S.P1InactiveInScope
            P2InactiveInScope       = [int]$S.P2InactiveInScope
            InactiveDays            = [int]$S.InactiveDays
            SignInDataAvailable     = [bool]$S.SignInDataAvailable
            ProvisioningExcluded    = [int]$S.ProvisioningExcluded
            P1UserGaps              = [int]$S.P1UserGaps
            P2UserGaps              = [int]$S.P2UserGaps
            P1InScopeWithReportOnly = [int]$S.P1InScopeWithReportOnly
            P2InScopeWithReportOnly = [int]$S.P2InScopeWithReportOnly
            EnforcedPolicies        = [int]$S.EnforcedPolicies
            EnforcedRiskPolicies    = [int]$S.EnforcedRiskPolicies
            EnabledMembers          = [int]$S.EnabledMembers
            NonPersonExcluded       = [int]$S.NonPersonExcluded
            GuestsInScope           = [int]$S.GuestsInScope
            Warnings                = @($Report.Findings | Where-Object Severity -EQ 'Warning').Count
        } | Out-Null
    } catch {
        Write-Information "Entra entitlement: could not store the summary for $($TenantFilter): $($_.Exception.Message)"
    }
}
