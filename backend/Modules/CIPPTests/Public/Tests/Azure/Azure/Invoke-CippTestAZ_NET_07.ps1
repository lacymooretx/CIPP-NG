function Invoke-CippTestAZ_NET_07 {
    <#
    .SYNOPSIS
    Azure - Network Watcher is enabled in every region with virtual networks
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_NET_07' -Name 'Network Watcher is enabled in every region with virtual networks' -Risk 'Low' -Category 'Network' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.network/virtualnetworks') -FailStatus 'Failed' -Requirement 'a Network Watcher exists in the same subscription and region' -Check {
            param($R)
            $W = @(Get-CippAzureResourcesOfType -Context $Ctx -Type 'microsoft.network/networkwatchers' | Where-Object { $_.subscriptionId -eq $R.subscriptionId -and $_.location -eq $R.location })
            if ($W.Count -eq 0) { "No Network Watcher in $($R.location)" }
        }
    }
}
