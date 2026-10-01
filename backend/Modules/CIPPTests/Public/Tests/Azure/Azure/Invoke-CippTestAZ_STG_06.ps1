function Invoke-CippTestAZ_STG_06 {
    <#
    .SYNOPSIS
    Azure - Storage accounts disallow cross-tenant replication
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_STG_06' -Name 'Storage accounts disallow cross-tenant replication' -Risk 'Low' -Category 'Storage' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.storage/storageaccounts') -FailStatus 'Failed' -Requirement 'cross-tenant object replication disallowed' -Check {
            param($R)
            if ($R.properties.allowCrossTenantReplication -eq $true) { 'Object replication to other tenants allowed' }
        }
    }
}
