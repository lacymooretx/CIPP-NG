function Get-CIPPIntunePolicyHygiene {
    <#
    .SYNOPSIS
        Intune assignment hygiene for a tenant: unassigned policies, exclusion-only policies, and assignments to
        groups that are gone or empty.
    .DESCRIPTION
        Read-only. Reads every policy family with assignments (Get-CIPPIntuneAssignablePolicies, assigned apps
        included), then each referenced group (/groups/{id}) and one member (/groups/{id}/members?$top=1) in a
        batch. A 404 on the group is "missing"; any other failure leaves the group unknown, never missing or empty.
        "Empty" means no direct members of any kind; a group whose only member is another (empty) group is not
        flagged. Evaluated with Test-CIPPIntunePolicyHygiene.
        Returns @{ Tenant; Findings; Summary; Errors }. Aspendora fork addition (Vikunja CIPP-19).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    $Collected = Get-CIPPIntuneAssignablePolicies -TenantFilter $TenantFilter -IncludeApps
    $Errors = [System.Collections.Generic.List[string]]::new()
    foreach ($E in $Collected.Errors) { $Errors.Add($E) }

    $GroupIds = @($Collected.Policies | ForEach-Object { $_.Assignments } | ForEach-Object { [string]$_.target.groupId } | Where-Object { $_ } | Sort-Object -Unique)
    $Groups = @{}
    if ($GroupIds.Count -gt 0) {
        $Requests = [System.Collections.Generic.List[object]]::new()
        $MemberIds = [System.Collections.Generic.List[string]]::new()
        foreach ($Id in $GroupIds) {
            $Requests.Add([pscustomobject]@{ id = "g-$Id"; method = 'GET'; url = "/groups/$Id`?`$select=id,displayName,groupTypes,membershipRule" })
            $Requests.Add([pscustomobject]@{ id = "m-$Id"; method = 'GET'; url = "/groups/$Id/members?`$select=id&`$top=1" })
            $MemberIds.Add("m-$Id")
        }
        $Results = @(New-GraphBulkRequest -Requests @($Requests) -tenantid $TenantFilter -NoPaginateIds @($MemberIds))
        $ById = @{}
        foreach ($R in $Results) { $ById[[string]$R.id] = $R }
        $Unreadable = 0
        foreach ($Id in $GroupIds) {
            $G = $ById["g-$Id"]
            $M = $ById["m-$Id"]
            $Entry = @{ Exists = $null; DisplayName = $null; MemberCount = $null; Dynamic = $false }
            if ($G -and $G.status -ge 200 -and $G.status -lt 300) {
                $Entry.Exists = $true
                $Entry.DisplayName = [string]$G.body.displayName
                $Entry.Dynamic = @($G.body.groupTypes) -contains 'DynamicMembership'
                if ($M -and $M.status -ge 200 -and $M.status -lt 300) { $Entry.MemberCount = @($M.body.value | Where-Object { $_ }).Count }
            } elseif ($G -and $G.status -eq 404) {
                $Entry.Exists = $false
            } else {
                $Unreadable++
            }
            $Groups[$Id] = $Entry
        }
        if ($Unreadable -gt 0) { $Errors.Add("$Unreadable assigned group(s) could not be read, so they are not checked for missing/empty.") }
    }

    $Report = Test-CIPPIntunePolicyHygiene -Policies $Collected.Policies -Groups $Groups

    # Per-type totals, so "3 unassigned" can be read against how many of that type exist.
    $Totals = [ordered]@{}
    foreach ($T in @($Collected.Policies | Group-Object Type | Sort-Object Name)) {
        $Totals[$T.Name] = [pscustomobject]@{
            Total      = $T.Count
            Unassigned = @($Report.Findings | Where-Object { $_.Category -eq 'Unassigned' -and $_.PolicyType -eq $T.Name }).Count
        }
    }
    $Report.Summary | Add-Member -NotePropertyName PolicyTypes -NotePropertyValue ([pscustomobject]$Totals) -Force
    $Report.Summary | Add-Member -NotePropertyName GroupsChecked -NotePropertyValue $GroupIds.Count -Force

    [pscustomobject]@{
        Tenant   = $TenantFilter
        Findings = @($Report.Findings)
        Summary  = $Report.Summary
        Errors   = @($Errors)
    }
}
