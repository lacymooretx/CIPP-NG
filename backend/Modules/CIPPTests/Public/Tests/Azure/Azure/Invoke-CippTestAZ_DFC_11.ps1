function Invoke-CippTestAZ_DFC_11 {
    <#
    .SYNOPSIS
    Azure - Defender for Endpoint integration is on
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_11' -Name 'Defender for Endpoint integration is on' -Risk 'Medium' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureSubscriptionCheck -Context $Ctx -FailStatus 'Failed' -Requirement 'the WDATP (Defender for Endpoint) integration setting is enabled' -Check {
            param($SubId)
            $D = $Ctx.Defender[$SubId.ToLower()]
            if (-not $D) { return '#skip:no Defender data collected' }
            if (@(Get-CippAzureResourcesOfType -Context $Ctx -Type 'microsoft.compute/virtualmachines' | Where-Object { $_.subscriptionId -eq $SubId }).Count -eq 0) { return '#skip:no VMs' }
            if ($D.securityProviderRegistered -eq $false) { return 'Defender for Cloud not activated' }
            if ($null -eq $D.settings) { return "#skip:settings unavailable ($($D.errors.settings))" }
            $Wdatp = $D.settings | Where-Object { $_.name -eq 'WDATP' } | Select-Object -First 1
            if (-not $Wdatp -or $Wdatp.properties.enabled -ne $true) { 'Defender for Endpoint integration is off' }
        }
    }
}
