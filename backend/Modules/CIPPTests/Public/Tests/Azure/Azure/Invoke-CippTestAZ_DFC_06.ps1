function Invoke-CippTestAZ_DFC_06 {
    <#
    .SYNOPSIS
    Azure - Defender for App Service is enabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_06' -Name 'Defender for App Service is enabled' -Risk 'Medium' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureDefenderPlanCheck -Context $Ctx -PlanNames @('AppServices') -PlanLabel 'Defender for App Service' -AppliesToTypes @('microsoft.web/sites')
    }
}
