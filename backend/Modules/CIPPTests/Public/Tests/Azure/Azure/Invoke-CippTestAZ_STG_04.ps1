function Invoke-CippTestAZ_STG_04 {
    <#
    .SYNOPSIS
    Azure - Storage accounts restrict public network access
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_STG_04' -Name 'Storage accounts restrict public network access' -Risk 'Medium' -Category 'Storage' -UserImpact 'Medium' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.storage/storageaccounts') -FailStatus 'Failed' -Requirement 'public network access disabled, or firewall default action Deny' -Check {
            param($R)
            if ($R.properties.publicNetworkAccess -ne 'Disabled' -and $R.properties.networkAcls.defaultAction -ne 'Deny') { 'Reachable from all networks' }
        }
    }
}
