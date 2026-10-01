function Invoke-CippTestAZ_DFC_04 {
    <#
    .SYNOPSIS
    Azure - Defender for Key Vault is enabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_04' -Name 'Defender for Key Vault is enabled' -Risk 'Medium' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureDefenderPlanCheck -Context $Ctx -PlanNames @('KeyVaults') -PlanLabel 'Defender for Key Vault' -AppliesToTypes @('microsoft.keyvault/vaults')
    }
}
