function Invoke-CippTestAZ_NET_03 {
    <#
    .SYNOPSIS
    Azure - No rule allows all ports from the internet
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_NET_03' -Name 'No rule allows all ports from the internet' -Risk 'High' -Category 'Network' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.network/networksecuritygroups') -FailStatus 'Failed' -Requirement 'no inbound rule allows every port from the internet' -Check {
            param($R)
            $Hits = @(Test-CippAzureNsgExposure -Nsg $R -Protocol '*')
            if ($Hits.Count) { $Hits -join '; ' }
        }
    }
}
