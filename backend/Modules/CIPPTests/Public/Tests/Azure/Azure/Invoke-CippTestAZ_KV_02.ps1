function Invoke-CippTestAZ_KV_02 {
    <#
    .SYNOPSIS
    Azure - Key vaults use Azure RBAC permissions
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_KV_02' -Name 'Key vaults use Azure RBAC permissions' -Risk 'Low' -Category 'Key Vault' -UserImpact 'Medium' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.keyvault/vaults') -FailStatus 'Investigate' -Requirement 'Azure RBAC permission model' -Check {
            param($R)
            if ($R.properties.enableRbacAuthorization -ne $true) { 'Uses legacy vault access policies' }
        }
    }
}
