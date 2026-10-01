function Invoke-CippTestAZ_KV_01 {
    <#
    .SYNOPSIS
    Azure - Key vaults have purge protection
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_KV_01' -Name 'Key vaults have purge protection' -Risk 'Medium' -Category 'Key Vault' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.keyvault/vaults') -FailStatus 'Failed' -Requirement 'purge protection enabled' -Check {
            param($R)
            if ($R.properties.enablePurgeProtection -ne $true) { 'Purge protection off: a deleted vault can be purged immediately' }
        }
    }
}
