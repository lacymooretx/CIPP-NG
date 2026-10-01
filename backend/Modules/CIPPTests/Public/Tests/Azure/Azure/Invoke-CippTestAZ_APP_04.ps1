function Invoke-CippTestAZ_APP_04 {
    <#
    .SYNOPSIS
    Azure - Web apps have remote debugging off
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_APP_04' -Name 'Web apps have remote debugging off' -Risk 'Medium' -Category 'App Service' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.web/sites') -FailStatus 'Failed' -Requirement 'remote debugging disabled' -Check {
            param($R)
            $C = $Ctx.Config[([string]$R.id).ToLower()]
            if (-not $C -or $C.errors.siteConfig) { return '#skip:site config unavailable' }
            if ($C.config.siteConfig.properties.remoteDebuggingEnabled -eq $true) { 'Remote debugging enabled' }
        }
    }
}
