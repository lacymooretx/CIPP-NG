function Invoke-CippTestAZ_RBAC_02 {
    <#
    .SYNOPSIS
    Azure - No guest users hold privileged Azure roles
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_RBAC_02' -Name 'No guest users hold privileged Azure roles' -Risk 'High' -Category 'Identity & Access' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        $Priv = @('Owner', 'Contributor', 'User Access Administrator', 'Role Based Access Control Administrator')
        $Bad = @($Ctx.RoleAssignments | Where-Object { $Priv -contains $_.roleName -and $_.principalUserType -eq 'Guest' })
        if ($Bad.Count -eq 0) { return @{ Status = 'Passed'; Markdown = 'No guest user holds Owner, Contributor, User Access Administrator or RBAC Administrator.' } }
        $Rows = $Bad | ForEach-Object { [ordered]@{ Guest = $_.principalUpn ?? $_.principalDisplayName; Role = $_.roleName; State = $_.assignmentState; Scope = $_.scope } }
        @{ Status = 'Failed'; Markdown = "$($Bad.Count) privileged role assignment(s) held by guest users:`n`n$(Format-CippAzureFindingTable -Rows $Rows)" }
    }
}
