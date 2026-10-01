function Invoke-CippTestAZ_DFC_02 {
    <#
    .SYNOPSIS
    Azure - Defender for Servers is enabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_02' -Name 'Defender for Servers is enabled' -Risk 'High' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureDefenderPlanCheck -Context $Ctx -PlanNames @('VirtualMachines') -PlanLabel 'Defender for Servers' -AppliesToTypes @('microsoft.compute/virtualmachines')
    }
}
