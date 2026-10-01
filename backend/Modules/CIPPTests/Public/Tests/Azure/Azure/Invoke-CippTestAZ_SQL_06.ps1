function Invoke-CippTestAZ_SQL_06 {
    <#
    .SYNOPSIS
    Azure - Azure SQL public endpoint is disabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_SQL_06' -Name 'Azure SQL public endpoint is disabled' -Risk 'Low' -Category 'Databases' -UserImpact 'Medium' -ImplementationEffort 'High' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.sql/servers') -FailStatus 'Investigate' -Requirement 'public network access disabled (private endpoint only)' -Check {
            param($R)
            if ($R.properties.publicNetworkAccess -ne 'Disabled') { 'Public endpoint enabled' }
        }
    }
}
