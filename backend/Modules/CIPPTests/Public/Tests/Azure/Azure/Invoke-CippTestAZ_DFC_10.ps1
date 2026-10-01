function Invoke-CippTestAZ_DFC_10 {
    <#
    .SYNOPSIS
    Azure - Email notifications are sent for high-severity alerts
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_10' -Name 'Email notifications are sent for high-severity alerts' -Risk 'Medium' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureSubscriptionCheck -Context $Ctx -FailStatus 'Failed' -Requirement 'alert notifications are on for High severity (or lower threshold)' -Check {
            param($SubId)
            $D = $Ctx.Defender[$SubId.ToLower()]
            if (-not $D) { return '#skip:no Defender data collected' }
            if ($D.securityProviderRegistered -eq $false) { return '#skip:Defender for Cloud not activated (see AZ_DFC_01)' }
            if ($null -eq $D.securityContacts) { return "#skip:contacts unavailable ($($D.errors.securityContacts))" }
            $On = @($D.securityContacts | Where-Object { $_.properties.alertNotifications.state -eq 'On' -and $_.properties.alertNotifications.minimalSeverity -in @('High', 'Medium', 'Low') })
            if ($On.Count -eq 0) { 'Alert email notifications are off' }
        }
    }
}
