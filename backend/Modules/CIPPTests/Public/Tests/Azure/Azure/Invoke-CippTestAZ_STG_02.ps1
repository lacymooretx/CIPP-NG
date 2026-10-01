function Invoke-CippTestAZ_STG_02 {
    <#
    .SYNOPSIS
    Azure - Storage accounts require TLS 1.2 or later
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_STG_02' -Name 'Storage accounts require TLS 1.2 or later' -Risk 'High' -Category 'Storage' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.storage/storageaccounts') -FailStatus 'Failed' -Requirement 'minimum TLS version 1.2' -Check {
            param($R)
            if ($R.properties.minimumTlsVersion -notin @('TLS1_2', 'TLS1_3')) { "Minimum TLS is $($R.properties.minimumTlsVersion ?? 'TLS1_0 (default)')" }
        }
    }
}
