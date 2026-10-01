function Invoke-CippTestAZ_DFC_05 {
    <#
    .SYNOPSIS
    Azure - Defender for Azure SQL is enabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_05' -Name 'Defender for Azure SQL is enabled' -Risk 'Medium' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureDefenderPlanCheck -Context $Ctx -PlanNames @('SqlServers') -PlanLabel 'Defender for Azure SQL' -AppliesToTypes @('microsoft.sql/servers')
    }
}
