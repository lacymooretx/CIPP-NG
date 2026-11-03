function Get-CIPPConditionalAccessPlans {
    <#
    .SYNOPSIS
        Reads a tenant's Conditional Access policy plans and their rules from Graph. Read only.
    .DESCRIPTION
        Plans exist only on beta (v1.0 returns 400) and their rules do not appear under
        identity/conditionalAccess/policies, so nothing else in CIPP sees them. Emits one object per plan with
        rules, ruleCount and rulesComplete added. Reads delegated first, then as the app: the partner tenant's
        delegated token has no roles, and CIPP-SAM can already read plans.

        Throws when the plan list cannot be read, because "could not check" is not "no plans". A failed rules
        read for one plan does not throw: the plan still exists, and ruleCount falls back to rules@odata.count
        with rulesComplete false.
        Aspendora fork addition (Vikunja CIPP-56).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    $Base = 'https://graph.microsoft.com/beta/identity/conditionalAccess/plans'
    $Read = {
        param($Uri)
        try {
            New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -ErrorAction Stop
        } catch {
            New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -AsApp $true -ErrorAction Stop
        }
    }

    foreach ($Plan in @(& $Read $Base | Where-Object { $_.id })) {
        $Complete = $true
        try {
            $Rules = @(& $Read "$Base/$($Plan.id)/rules" | Where-Object { $_.id })
            $Count = $Rules.Count
        } catch {
            $Complete = $false
            $Rules = @($Plan.rules | Where-Object { $_.id })
            $Count = [math]::Max($Rules.Count, [int]($Plan.'rules@odata.count' ?? 0))
        }
        $Plan | Add-Member -NotePropertyName rules -NotePropertyValue $Rules -Force
        $Plan | Add-Member -NotePropertyName ruleCount -NotePropertyValue $Count -Force
        $Plan | Add-Member -NotePropertyName rulesComplete -NotePropertyValue $Complete -Force
        $Plan
    }
}
