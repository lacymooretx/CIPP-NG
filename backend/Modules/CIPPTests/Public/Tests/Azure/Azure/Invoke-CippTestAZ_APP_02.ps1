function Invoke-CippTestAZ_APP_02 {
    <#
    .SYNOPSIS
    Azure - Web apps require TLS 1.2 or later
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_APP_02' -Name 'Web apps require TLS 1.2 or later' -Risk 'High' -Category 'App Service' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.web/sites') -FailStatus 'Failed' -Requirement 'minimum inbound TLS 1.2' -Check {
            param($R)
            $C = $Ctx.Config[([string]$R.id).ToLower()]
            if (-not $C -or $C.errors.siteConfig) { return '#skip:site config unavailable' }
            if ($C.config.siteConfig.properties.minTlsVersion -notin @('1.2', '1.3')) { "Minimum TLS $($C.config.siteConfig.properties.minTlsVersion)" }
        }
    }
}
