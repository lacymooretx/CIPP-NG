function Invoke-CippTestAZ_DFC_07 {
    <#
    .SYNOPSIS
    Azure - Defender for Resource Manager is enabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_07' -Name 'Defender for Resource Manager is enabled' -Risk 'Medium' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureDefenderPlanCheck -Context $Ctx -PlanNames @('Arm') -PlanLabel 'Defender for Resource Manager'
    }
}
