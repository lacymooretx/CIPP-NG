function Invoke-CippTestAZ_STG_03 {
    <#
    .SYNOPSIS
    Azure - Storage accounts disallow anonymous blob access
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_STG_03' -Name 'Storage accounts disallow anonymous blob access' -Risk 'High' -Category 'Storage' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.storage/storageaccounts') -FailStatus 'Failed' -Requirement 'blob anonymous access disallowed' -Check {
            param($R)
            if ($R.kind -eq 'FileStorage') { return '#skip:file-only account' }
            if ($R.properties.allowBlobPublicAccess -eq $true) { 'Anonymous (public) blob access is allowed' }
            elseif ($null -eq $R.properties.allowBlobPublicAccess) { 'Anonymous access not explicitly disallowed (older accounts default to allowed)' }
        }
    }
}
