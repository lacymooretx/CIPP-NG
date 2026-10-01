function Invoke-CippTestAZ_DFC_08 {
    <#
    .SYNOPSIS
    Azure - Defender for Containers is enabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_08' -Name 'Defender for Containers is enabled' -Risk 'Medium' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureDefenderPlanCheck -Context $Ctx -PlanNames @('Containers') -PlanLabel 'Defender for Containers' -AppliesToTypes @('microsoft.containerservice/managedclusters', 'microsoft.containerregistry/registries')
    }
}
