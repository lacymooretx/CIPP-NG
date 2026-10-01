function Invoke-CippTestAZ_RBAC_06 {
    <#
    .SYNOPSIS
    Azure - Privileged user access is just-in-time, not permanent
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_RBAC_06' -Name 'Privileged user access is just-in-time, not permanent' -Risk 'Medium' -Category 'Identity & Access' -UserImpact 'Medium' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        $Admin = @('Owner', 'User Access Administrator', 'Role Based Access Control Administrator')
        $Standing = @($Ctx.RoleAssignments | Where-Object { $_.principalType -eq 'User' -and $Admin -contains $_.roleName -and $_.assignmentState -eq 'Active' })
        $Eligible = @($Ctx.RoleAssignments | Where-Object { $Admin -contains $_.roleName -and $_.assignmentState -eq 'Eligible' })
        if ($Standing.Count -eq 0) { return @{ Status = 'Passed'; Markdown = "No user holds a permanent Owner / access-management assignment. $($Eligible.Count) eligible (PIM) assignment(s) in use." } }
        $Rows = $Standing | ForEach-Object { [ordered]@{ User = $_.principalUpn ?? $_.principalDisplayName; Role = $_.roleName; Scope = $_.scope } }
        @{ Status = 'Investigate'; Markdown = "$($Standing.Count) permanent privileged assignment(s) to users ($($Eligible.Count) eligible PIM assignment(s) exist). A just-activated PIM assignment also shows as active, so confirm before acting:`n`n$(Format-CippAzureFindingTable -Rows $Rows)" }
    }
}
