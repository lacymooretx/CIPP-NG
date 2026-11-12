function Test-CIPPBreakGlassCAReadback {
    <#
    .SYNOPSIS
        Compares a Conditional Access policy before and after the break-glass exclusion PATCH.
    .DESCRIPTION
        The only allowed difference is the group added to excludeGroups. State, every other user list, grant and
        session controls and the other conditions must be identical. Graph can return 2xx and ignore or reshape a
        change, so a 204 is not proof.
        Pure function. Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Before,
        [Parameter(Mandatory)]$After,
        [Parameter(Mandatory)][string]$GroupId
    )
    $Problems = [System.Collections.Generic.List[string]]::new()
    $Norm = { param($L) @($L | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object) -join ',' }

    if ([string]$Before.state -ne [string]$After.state) { $Problems.Add("state changed from '$($Before.state)' to '$($After.state)'") }

    $AfterGroups = @($After.conditions.users.excludeGroups)
    if ($AfterGroups -notcontains $GroupId) { $Problems.Add('the break-glass group is not in excludeGroups after the update') }
    $Expected = & $Norm (@($Before.conditions.users.excludeGroups) + $GroupId | Select-Object -Unique)
    if ((& $Norm $AfterGroups) -ne $Expected) { $Problems.Add('excludeGroups changed beyond adding the break-glass group') }

    foreach ($Name in 'includeUsers', 'excludeUsers', 'includeGroups', 'includeRoles', 'excludeRoles') {
        if ((& $Norm $Before.conditions.users.$Name) -ne (& $Norm $After.conditions.users.$Name)) { $Problems.Add("$Name changed") }
    }

    $Json = { param($O) if ($null -eq $O) { '' } else { ConvertTo-Json -InputObject $O -Depth 20 -Compress } }
    foreach ($Name in 'grantControls', 'sessionControls') {
        if ((& $Json $Before.$Name) -ne (& $Json $After.$Name)) { $Problems.Add("$Name changed") }
    }
    foreach ($Name in 'applications', 'platforms', 'locations', 'clientAppTypes', 'signInRiskLevels', 'userRiskLevels', 'devices') {
        if ((& $Json $Before.conditions.$Name) -ne (& $Json $After.conditions.$Name)) { $Problems.Add("conditions.$Name changed") }
    }
    return [pscustomobject]@{ Ok = ($Problems.Count -eq 0); Problems = @($Problems) }
}
