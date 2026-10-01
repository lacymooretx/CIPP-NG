function Invoke-CippTestAZ_DFC_03 {
    <#
    .SYNOPSIS
    Azure - Defender for Storage is enabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_03' -Name 'Defender for Storage is enabled' -Risk 'Medium' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureDefenderPlanCheck -Context $Ctx -PlanNames @('StorageAccounts') -PlanLabel 'Defender for Storage' -AppliesToTypes @('microsoft.storage/storageaccounts')
    }
}
