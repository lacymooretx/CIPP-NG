function Invoke-CippTestAZ_RBAC_05 {
    <#
    .SYNOPSIS
    Azure - No custom roles grant all actions
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_RBAC_05' -Name 'No custom roles grant all actions' -Risk 'Medium' -Category 'Identity & Access' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        $Wild = @($Ctx.CustomRoles | Where-Object { @($_.permissions | ForEach-Object { $_.actions }) -contains '*' })
        if ($Wild.Count -eq 0) { return @{ Status = 'Passed'; Markdown = "No custom role grants '*' (all actions). $(@($Ctx.CustomRoles).Count) custom role(s) reviewed." } }
        $Rows = $Wild | ForEach-Object { [ordered]@{ Role = $_.roleName; 'Assignable scopes' = (@($_.assignableScopes) -join ', ') } }
        @{ Status = 'Failed'; Markdown = "$($Wild.Count) custom role(s) grant all actions, which makes them Owner-equivalent under another name:`n`n$(Format-CippAzureFindingTable -Rows $Rows)" }
    }
}
