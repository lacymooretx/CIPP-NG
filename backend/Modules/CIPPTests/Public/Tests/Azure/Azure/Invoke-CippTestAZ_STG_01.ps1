function Invoke-CippTestAZ_STG_01 {
    <#
    .SYNOPSIS
    Azure - Storage accounts require secure transfer (HTTPS)
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_STG_01' -Name 'Storage accounts require secure transfer (HTTPS)' -Risk 'High' -Category 'Storage' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.storage/storageaccounts') -FailStatus 'Failed' -Requirement 'secure transfer required (HTTPS only)' -Check {
            param($R)
            if ($R.properties.supportsHttpsTrafficOnly -ne $true) { 'Secure transfer disabled: HTTP allowed' }
        }
    }
}
