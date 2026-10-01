function Invoke-CippTestAZ_AKS_02 {
    <#
    .SYNOPSIS
    Azure - AKS API servers are not open to the whole internet
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_AKS_02' -Name 'AKS API servers are not open to the whole internet' -Risk 'Medium' -Category 'Containers' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.containerservice/managedclusters') -FailStatus 'Failed' -Requirement 'private cluster or authorised IP ranges set' -Check {
            param($R)
            $A = $R.properties.apiServerAccessProfile
            if ($A.enablePrivateCluster -ne $true -and @($A.authorizedIPRanges).Count -eq 0) { 'Public API server reachable from any IP' }
        }
    }
}
