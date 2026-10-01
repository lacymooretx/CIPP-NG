function Invoke-CippTestAZ_APP_03 {
    <#
    .SYNOPSIS
    Azure - Web apps do not allow plain FTP
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_APP_03' -Name 'Web apps do not allow plain FTP' -Risk 'Medium' -Category 'App Service' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.web/sites') -FailStatus 'Failed' -Requirement 'FTP state Disabled or FTPS only' -Check {
            param($R)
            $C = $Ctx.Config[([string]$R.id).ToLower()]
            if (-not $C -or $C.errors.siteConfig) { return '#skip:site config unavailable' }
            if ($C.config.siteConfig.properties.ftpsState -eq 'AllAllowed') { 'Plain FTP allowed (credentials in clear text)' }
        }
    }
}
