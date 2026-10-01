function Invoke-CippTestAZ_GOV_01 {
    <#
    .SYNOPSIS
    Azure - Microsoft cloud security benchmark policy is assigned
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_GOV_01' -Name 'Microsoft cloud security benchmark policy is assigned' -Risk 'Medium' -Category 'Governance' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureSubscriptionCheck -Context $Ctx -FailStatus 'Failed' -Requirement 'the Microsoft cloud security benchmark initiative is assigned at or above the subscription' -Check {
            param($SubId)
            $Mcsb = @($Ctx.Policy | Where-Object { ([string]$_.policyDefinitionId).ToLower().EndsWith('/1f3afdf9-d0c9-4c3d-847f-89da613e70a8') })
            $Hit = @($Mcsb | Where-Object { $_.subscriptionId -eq $SubId -or $_.scope -like '/providers/Microsoft.Management/managementGroups/*' })
            if ($Hit.Count -eq 0) { 'Initiative not assigned' }
        }
    }
}
