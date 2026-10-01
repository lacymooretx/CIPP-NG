function Invoke-CippTestAZ_AKS_01 {
    <#
    .SYNOPSIS
    Azure - AKS clusters disable local accounts
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_AKS_01' -Name 'AKS clusters disable local accounts' -Risk 'Medium' -Category 'Containers' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.containerservice/managedclusters') -FailStatus 'Failed' -Requirement 'local accounts disabled (Entra-only access)' -Check {
            param($R)
            if ($R.properties.disableLocalAccounts -ne $true) { 'Local (certificate) admin accounts enabled' }
        }
    }
}
