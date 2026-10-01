function Invoke-CippTestAZ_NET_08 {
    <#
    .SYNOPSIS
    Azure - Virtual machines do not have public IP addresses
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_NET_08' -Name 'Virtual machines do not have public IP addresses' -Risk 'Medium' -Category 'Network' -UserImpact 'Medium' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.compute/virtualmachines') -FailStatus 'Investigate' -Requirement 'no public IP attached to the VM network interfaces' -Check {
            param($R)
            $NicIds = @($R.properties.networkProfile.networkInterfaces | ForEach-Object { ([string]$_.id).ToLower() })
            $Nics = @(Get-CippAzureResourcesOfType -Context $Ctx -Type 'microsoft.network/networkinterfaces' | Where-Object { $NicIds -contains ([string]$_.id).ToLower() })
            $PipIds = @($Nics | ForEach-Object { $_.properties.ipConfigurations } | ForEach-Object { $_.properties.publicIPAddress.id } | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLower() })
            if ($PipIds.Count -eq 0) { return $null }
            $Pips = @(Get-CippAzureResourcesOfType -Context $Ctx -Type 'microsoft.network/publicipaddresses' | Where-Object { $PipIds -contains ([string]$_.id).ToLower() })
            "Public IP: $((@($Pips | ForEach-Object { $_.properties.ipAddress ?? $_.name }) -join ', '))"
        }
    }
}
