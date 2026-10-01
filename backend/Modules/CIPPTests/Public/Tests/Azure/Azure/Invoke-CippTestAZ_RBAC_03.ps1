function Invoke-CippTestAZ_RBAC_03 {
    <#
    .SYNOPSIS
    Azure - No role assignments for deleted principals
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_RBAC_03' -Name 'No role assignments for deleted principals' -Risk 'Low' -Category 'Identity & Access' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        $Orphans = @($Ctx.RoleAssignments | Where-Object { -not $_.principalResolved -and $_.principalType -ne 'ForeignGroup' })
        if ($Orphans.Count -eq 0) { return @{ Status = 'Passed'; Markdown = 'Every role assignment resolves to an existing user, group or service principal.' } }
        $Rows = $Orphans | ForEach-Object { [ordered]@{ 'Principal id' = $_.principalId; 'Type' = $_.principalType; Role = $_.roleName; Scope = $_.scope } }
        @{ Status = 'Failed'; Markdown = "$($Orphans.Count) role assignment(s) point at principals that no longer exist in the directory (shown as 'Identity not found' in the portal):`n`n$(Format-CippAzureFindingTable -Rows $Rows)" }
    }
}
