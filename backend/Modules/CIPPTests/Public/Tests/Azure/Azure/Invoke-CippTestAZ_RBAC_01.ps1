function Invoke-CippTestAZ_RBAC_01 {
    <#
    .SYNOPSIS
    Azure - No more than three owners per subscription
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_RBAC_01' -Name 'No more than three owners per subscription' -Risk 'Medium' -Category 'Identity & Access' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        $Rows = foreach ($Sub in $Ctx.Subscriptions) {
            $SubScope = "/subscriptions/$($Sub.subscriptionId)"
            $Owners = @($Ctx.RoleAssignments | Where-Object {
                    $_.roleName -eq 'Owner' -and $_.assignmentState -eq 'Active' -and
                    ($_.scope -eq $SubScope -or $_.scope -like '/providers/Microsoft.Management/managementGroups/*' -or $_.scope -eq '/')
                } | Sort-Object principalId -Unique)
            [ordered]@{
                Subscription = $Sub.displayName
                Owners       = $Owners.Count
                Principals   = (@($Owners | ForEach-Object { $_.principalDisplayName ?? "$($_.principalType) $($_.principalId)" }) -join ', ')
            }
        }
        $TooMany = @($Rows | Where-Object { $_.Owners -gt 3 })
        $TooFew = @($Rows | Where-Object { $_.Owners -lt 2 })
        $Status = if ($TooMany.Count) { 'Failed' } elseif ($TooFew.Count) { 'Investigate' } else { 'Passed' }
        $OutOfRange = @($TooMany) + @($TooFew)
        if ($OutOfRange.Count -eq 0) { return @{ Status = 'Passed'; Markdown = "All $(@($Rows).Count) subscription(s) have 2 or 3 owners (active, subscription or management-group scope)." } }
        @{ Status = $Status; Markdown = "$($TooMany.Count) subscription(s) have more than 3 owners and $($TooFew.Count) fewer than 2 (active, subscription or management-group scope). More than 3 widens the blast radius of one compromised account; fewer than 2 risks losing control of the subscription.`n`n$(Format-CippAzureFindingTable -Rows $OutOfRange)" }
    }
}
