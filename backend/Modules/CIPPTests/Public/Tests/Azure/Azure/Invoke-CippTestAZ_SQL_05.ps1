function Invoke-CippTestAZ_SQL_05 {
    <#
    .SYNOPSIS
    Azure - Azure SQL requires TLS 1.2 or later
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_SQL_05' -Name 'Azure SQL requires TLS 1.2 or later' -Risk 'Medium' -Category 'Databases' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.sql/servers') -FailStatus 'Failed' -Requirement 'minimal TLS version 1.2' -Check {
            param($R)
            if ($R.properties.minimalTlsVersion -notin @('1.2', '1.3')) { "Minimal TLS: $($R.properties.minimalTlsVersion ?? 'None (any)')" }
        }
    }
}
