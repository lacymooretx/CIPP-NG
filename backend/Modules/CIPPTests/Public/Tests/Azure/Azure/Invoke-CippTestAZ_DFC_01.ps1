function Invoke-CippTestAZ_DFC_01 {
    <#
    .SYNOPSIS
    Azure - Defender for Cloud is activated on every subscription
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_01' -Name 'Defender for Cloud is activated on every subscription' -Risk 'High' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureSubscriptionCheck -Context $Ctx -FailStatus 'Failed' -Requirement 'the Microsoft.Security resource provider is registered (Defender for Cloud active)' -Check {
            param($SubId)
            $D = $Ctx.Defender[$SubId.ToLower()]
            if (-not $D) { return '#skip:no Defender data collected' }
            if ($D.securityProviderRegistered -eq $false) { 'Defender for Cloud has never been activated on this subscription' }
        }
    }
}
