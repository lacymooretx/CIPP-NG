function Get-CIPPAsrReadiness {
    <#
    .SYNOPSIS
        Per-rule ASR audit-to-block readiness for one tenant.
    .DESCRIPTION
        Read-only. Combines:
          - the rule modes of the tenant's assigned ASR policies (Get-CIPPDefenderPolicyInventory +
            Resolve-CIPPAsrRuleModes; tenant level, not per device),
          - ASR hit counts over WindowDays from Get-CIPPAsrEvidence (advanced hunting when the tenant has the
            device tables, otherwise the ControlR collector rows in table AsrEvidence),
          - a recommendation per rule (Get-CIPPAsrRecommendation).
        Returns @{ Tenant; WindowDays; Evidence; Summary; Rules; Errors; Notes }. Report only: nothing is changed.
        Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [int]$WindowDays = 14,
        [switch]$SkipHunting
    )
    $Inventory = Get-CIPPDefenderPolicyInventory -TenantFilter $TenantFilter
    $PolicyRules = @($Inventory.Policies | Where-Object { @($_.Parsed.AsrRules).Count -gt 0 } | ForEach-Object {
            [pscustomobject]@{ PolicyId = $_.Id; PolicyName = $_.Name; Assigned = $_.Assigned; AssignmentLabel = $_.AssignmentLabel; Rules = @($_.Parsed.AsrRules) }
        })
    $Modes = @(Resolve-CIPPAsrRuleModes -PolicyRules $PolicyRules)
    $Evidence = Get-CIPPAsrEvidence -TenantFilter $TenantFilter -WindowDays $WindowDays -SkipHunting:$SkipHunting

    $Rules = foreach ($M in $Modes) {
        $RuleEvidence = if ($M.RuleId) { $Evidence.ByRule[$M.RuleId.ToUpperInvariant()] } else { $null }
        $Rec = Get-CIPPAsrRecommendation -Mode $M.EffectiveMode -Evidence $Evidence -RuleEvidence $RuleEvidence -WindowDays $WindowDays
        [pscustomobject]@{
            RuleId             = $M.RuleId
            Rule               = $M.Name
            Mode               = $M.EffectiveMode
            AuditHits          = [int]($RuleEvidence.Audited ?? 0) + [int]($RuleEvidence.Warned ?? 0)
            BlockHits          = [int]($RuleEvidence.Blocked ?? 0)
            DevicesWithHits    = [int]($RuleEvidence.Devices ?? 0)
            Recommendation     = $Rec.Recommendation
            Reason             = $Rec.Reason
            Policies           = ($M.Policies -join '; ')
            UnassignedPolicies = ($M.UnassignedPolicies -join '; ')
            Exclusions         = $M.ExclusionCount
        }
    }
    $Rules = @($Rules)
    $Count = { param($R) @($Rules | Where-Object { $_.Recommendation -eq $R }).Count }
    $Notes = @($Inventory.Notes) + @($Evidence.Notes)
    if ($PolicyRules.Count -eq 0) { $Notes = @('No Settings Catalog / endpoint security policy in this tenant sets ASR rules.') + $Notes }

    [pscustomobject]@{
        Tenant     = $TenantFilter
        WindowDays = $WindowDays
        Evidence   = [pscustomobject]@{
            Available           = $Evidence.Available
            Source              = $Evidence.Source
            CoverageDays        = $Evidence.CoverageDays
            DevicesReporting    = $Evidence.DevicesReporting
            DevicesWithoutRules = $Evidence.DevicesWithoutRules
        }
        Summary    = [pscustomobject]@{
            AsrPolicies   = $PolicyRules.Count
            Assigned      = @($PolicyRules | Where-Object { $_.Assigned -eq $true }).Count
            ReadyForBlock = & $Count 'ReadyForBlock'
            KeepAudit     = & $Count 'KeepAudit'
            AlreadyBlock  = & $Count 'AlreadyBlock'
            NotConfigured = & $Count 'NotConfigured'
            FixConflict   = & $Count 'FixConflict'
        }
        Rules      = $Rules
        Errors     = @($Inventory.Errors)
        Notes      = @($Notes)
    }
}
