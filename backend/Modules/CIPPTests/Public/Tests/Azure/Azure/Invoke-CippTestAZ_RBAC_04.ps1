function Invoke-CippTestAZ_RBAC_04 {
    <#
    .SYNOPSIS
    Azure - Service principals do not hold Owner or access-management roles
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_RBAC_04' -Name 'Service principals do not hold Owner or access-management roles' -Risk 'High' -Category 'Identity & Access' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        $Admin = @('Owner', 'User Access Administrator', 'Role Based Access Control Administrator')
        $Sps = @($Ctx.RoleAssignments | Where-Object { $_.principalType -eq 'ServicePrincipal' -and $Admin -contains $_.roleName -and $_.scope -notmatch '/resourceGroups/' })
        if ($Sps.Count -eq 0) { return @{ Status = 'Passed'; Markdown = 'No service principal holds Owner, User Access Administrator or RBAC Administrator at subscription scope or above.' } }
        $Rows = $Sps | ForEach-Object { [ordered]@{ 'Service principal' = $_.principalDisplayName ?? $_.principalId; 'Third-party' = $(if ($_.principalExternal) { 'Yes' } else { 'No' }); Role = $_.roleName; Scope = $_.scope } }
        $Status = if (@($Sps | Where-Object { $_.principalExternal -or -not $_.principalResolved }).Count) { 'Failed' } else { 'Investigate' }
        @{ Status = $Status; Markdown = "$($Sps.Count) service principal assignment(s) can change access to the subscription. Their credentials (secrets/certificates) are a full-subscription takeover path:`n`n$(Format-CippAzureFindingTable -Rows $Rows)" }
    }
}
