function New-CIPPBreakGlassCAPatch {
    <#
    .SYNOPSIS
        Builds the PATCH body that adds the break-glass exclusion group to one Conditional Access policy.
    .DESCRIPTION
        Re-sends the policy's whole conditions.users block with only the group added to excludeGroups, the method
        used for the 2026-10-31 remediation (Hudu 737). Sending a partial users block is what wipes lists on CA
        plans, so nothing is left for Graph to merge. Returns $null when the policy already excludes the group.
        Pure function. Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][string]$GroupId
    )
    $Users = $Policy.conditions.users
    $Existing = @($Users.excludeGroups | Where-Object { $_ })
    if ($Existing -contains $GroupId) { return $null }

    $Block = [ordered]@{}
    foreach ($Name in 'includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups', 'includeRoles', 'excludeRoles') {
        $Block[$Name] = @($Users.$Name | Where-Object { $_ })
    }
    foreach ($Name in 'includeGuestsOrExternalUsers', 'excludeGuestsOrExternalUsers') {
        if ($null -ne $Users.$Name) { $Block[$Name] = $Users.$Name }
    }
    $Block['excludeGroups'] = @($Existing + $GroupId)
    return [pscustomobject]@{ conditions = [pscustomobject]@{ users = [pscustomobject]$Block } }
}
