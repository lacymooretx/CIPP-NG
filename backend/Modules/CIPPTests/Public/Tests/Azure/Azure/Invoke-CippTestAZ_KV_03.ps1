function Invoke-CippTestAZ_KV_03 {
    <#
    .SYNOPSIS
    Azure - Key vaults restrict public network access
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_KV_03' -Name 'Key vaults restrict public network access' -Risk 'Medium' -Category 'Key Vault' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.keyvault/vaults') -FailStatus 'Failed' -Requirement 'public network access disabled, or firewall default action Deny' -Check {
            param($R)
            if ($R.properties.publicNetworkAccess -ne 'Disabled' -and $R.properties.networkAcls.defaultAction -ne 'Deny') { 'Reachable from all networks' }
        }
    }
}
