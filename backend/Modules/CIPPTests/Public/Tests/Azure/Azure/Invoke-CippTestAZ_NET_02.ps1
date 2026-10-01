function Invoke-CippTestAZ_NET_02 {
    <#
    .SYNOPSIS
    Azure - SSH is not open to the internet
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_NET_02' -Name 'SSH is not open to the internet' -Risk 'High' -Category 'Network' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.network/networksecuritygroups') -FailStatus 'Failed' -Requirement 'no inbound rule allows SSH (22) from the internet' -Check {
            param($R)
            $Hits = @(Test-CippAzureNsgExposure -Nsg $R -Ports @(22) -Protocol 'Tcp')
            if ($Hits.Count) { $Hits -join '; ' }
        }
    }
}
