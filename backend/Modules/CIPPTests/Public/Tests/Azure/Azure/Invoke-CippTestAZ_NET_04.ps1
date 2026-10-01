function Invoke-CippTestAZ_NET_04 {
    <#
    .SYNOPSIS
    Azure - Common UDP services are not open to the internet
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_NET_04' -Name 'Common UDP services are not open to the internet' -Risk 'Medium' -Category 'Network' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.network/networksecuritygroups') -FailStatus 'Failed' -Requirement 'no inbound rule allows DNS/NTP/SNMP/CLDAP/SSDP over UDP from the internet' -Check {
            param($R)
            $Hits = @(Test-CippAzureNsgExposure -Nsg $R -Ports @(53, 123, 161, 389, 1900) -Protocol 'Udp')
            if ($Hits.Count) { $Hits -join '; ' }
        }
    }
}
