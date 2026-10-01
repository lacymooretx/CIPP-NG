function Invoke-CippTestAZ_DFC_09 {
    <#
    .SYNOPSIS
    Azure - Security alert contact email is configured
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_09' -Name 'Security alert contact email is configured' -Risk 'Medium' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureSubscriptionCheck -Context $Ctx -FailStatus 'Failed' -Requirement 'a security contact email is set' -Check {
            param($SubId)
            $D = $Ctx.Defender[$SubId.ToLower()]
            if (-not $D) { return '#skip:no Defender data collected' }
            if ($D.securityProviderRegistered -eq $false) { return '#skip:Defender for Cloud not activated (see AZ_DFC_01)' }
            if ($null -eq $D.securityContacts) { return "#skip:contacts unavailable ($($D.errors.securityContacts))" }
            $Emails = @($D.securityContacts | ForEach-Object { $_.properties.emails } | Where-Object { $_ })
            if ($Emails.Count -eq 0) { 'No security contact email' }
        }
    }
}
