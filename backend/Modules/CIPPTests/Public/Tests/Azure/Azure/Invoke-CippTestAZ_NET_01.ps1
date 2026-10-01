function Invoke-CippTestAZ_NET_01 {
    <#
    .SYNOPSIS
    Azure - RDP is not open to the internet
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_NET_01' -Name 'RDP is not open to the internet' -Risk 'High' -Category 'Network' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.network/networksecuritygroups') -FailStatus 'Failed' -Requirement 'no inbound rule allows RDP (3389) from the internet' -Check {
            param($R)
            $Hits = @(Test-CippAzureNsgExposure -Nsg $R -Ports @(3389) -Protocol 'Tcp')
            if ($Hits.Count) { $Hits -join '; ' }
        }
    }
}
