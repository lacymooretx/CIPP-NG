function Invoke-CippTestAZ_NET_06 {
    <#
    .SYNOPSIS
    Azure - Virtual networks have flow logs
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_NET_06' -Name 'Virtual networks have flow logs' -Risk 'Low' -Category 'Network' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.network/virtualnetworks') -FailStatus 'Investigate' -Requirement 'an enabled VNet flow log targets the virtual network' -Check {
            param($R)
            $Logs = @(Get-CippAzureResourcesOfType -Context $Ctx -Type 'microsoft.network/networkwatchers/flowlogs' | Where-Object { $_.properties.enabled -eq $true })
            if (-not ($Logs | Where-Object { ([string]$_.properties.targetResourceId).ToLower() -eq ([string]$R.id).ToLower() })) { 'No VNet flow log' }
        }
    }
}
