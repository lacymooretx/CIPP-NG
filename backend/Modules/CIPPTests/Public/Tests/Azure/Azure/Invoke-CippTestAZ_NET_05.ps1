function Invoke-CippTestAZ_NET_05 {
    <#
    .SYNOPSIS
    Azure - Database, file-sharing and remote-management ports are not open to the internet
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_NET_05' -Name 'Database, file-sharing and remote-management ports are not open to the internet' -Risk 'High' -Category 'Network' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.network/networksecuritygroups') -FailStatus 'Failed' -Requirement 'no inbound rule allows database/SMB/WinRM/Telnet/FTP ports from the internet' -Check {
            param($R)
            $Hits = @(Test-CippAzureNsgExposure -Nsg $R -Ports @(21, 23, 135, 139, 445, 1433, 1521, 3306, 5432, 5985, 5986, 6379, 9200, 27017) -Protocol 'Tcp')
            if ($Hits.Count) { $Hits -join '; ' }
        }
    }
}
