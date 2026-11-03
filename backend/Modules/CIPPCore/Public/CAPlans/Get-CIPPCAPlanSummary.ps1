function Get-CIPPCAPlanSummary {
    <#
    .SYNOPSIS
        Counts plans and rules and words the warning shown wherever CIPP evaluates Conditional Access.
    .DESCRIPTION
        Pure: takes plan objects from Get-CIPPConditionalAccessPlans or the ConditionalAccessPlans cache.
        Warning is $null when there are no plans. Aspendora fork addition (Vikunja CIPP-56).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([object[]]$Plans = @())

    $Found = @($Plans | Where-Object { $_.id })
    $RuleCount = 0
    foreach ($Plan in $Found) { $RuleCount += [int]($Plan.ruleCount ?? 0) }
    $Complete = @($Found | Where-Object { $_.rulesComplete -eq $false }).Count -eq 0
    $Rules = "$(if ($Complete) { '' } else { 'at least ' })$RuleCount rule$(if ($RuleCount -ne 1) { 's' })"
    [pscustomobject]@{
        PlanCount     = $Found.Count
        RuleCount     = $RuleCount
        RulesComplete = $Complete
        Warning       = if ($Found.Count -gt 0) {
            "This tenant has $($Found.Count) Conditional Access plan$(if ($Found.Count -ne 1) { 's' }) and $Rules that CIPP does not evaluate. Those rules are enforced, but they are missing from this view, so its results may be wrong."
        }
    }
}
