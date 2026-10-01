function Invoke-CippTestAZ_APP_01 {
    <#
    .SYNOPSIS
    Azure - Web apps are HTTPS only
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_APP_01' -Name 'Web apps are HTTPS only' -Risk 'High' -Category 'App Service' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.web/sites') -FailStatus 'Failed' -Requirement 'HTTPS only' -Check {
            param($R)
            if ($R.properties.httpsOnly -ne $true) { 'HTTP allowed' }
        }
    }
}
