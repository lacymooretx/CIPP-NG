function Invoke-CippTestAZ_SQL_04 {
    <#
    .SYNOPSIS
    Azure - Azure SQL uses Microsoft Entra-only authentication
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_SQL_04' -Name 'Azure SQL uses Microsoft Entra-only authentication' -Risk 'Low' -Category 'Databases' -UserImpact 'High' -ImplementationEffort 'High' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.sql/servers') -FailStatus 'Investigate' -Requirement 'Entra-only authentication (SQL logins disabled)' -Check {
            param($R)
            if ($R.properties.administrators.azureADOnlyAuthentication -ne $true) { 'SQL authentication (passwords) still enabled' }
        }
    }
}
