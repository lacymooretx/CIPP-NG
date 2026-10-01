function Invoke-CippTestAZ_STG_05 {
    <#
    .SYNOPSIS
    Azure - Storage accounts disable shared key access
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_STG_05' -Name 'Storage accounts disable shared key access' -Risk 'Low' -Category 'Storage' -UserImpact 'Medium' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.storage/storageaccounts') -FailStatus 'Investigate' -Requirement 'shared key (account key) authorisation disabled' -Check {
            param($R)
            if ($R.properties.allowSharedKeyAccess -ne $false) { 'Account keys can authorise requests' }
        }
    }
}
