function Invoke-CippTestAZ_APP_05 {
    <#
    .SYNOPSIS
    Azure - Web apps use a managed identity
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_APP_05' -Name 'Web apps use a managed identity' -Risk 'Low' -Category 'App Service' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.web/sites') -FailStatus 'Investigate' -Requirement 'system- or user-assigned managed identity' -Check {
            param($R)
            if (-not $R.identity -or $R.identity.type -in @('None', $null, '')) { 'No managed identity' }
        }
    }
}
