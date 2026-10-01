function Invoke-CippTestAZ_DB_01 {
    <#
    .SYNOPSIS
    Azure - PostgreSQL and MySQL flexible servers are not publicly reachable
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DB_01' -Name 'PostgreSQL and MySQL flexible servers are not publicly reachable' -Risk 'Low' -Category 'Databases' -UserImpact 'Medium' -ImplementationEffort 'High' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.dbforpostgresql/flexibleservers', 'microsoft.dbformysql/flexibleservers') -FailStatus 'Investigate' -Requirement 'public network access disabled' -Check {
            param($R)
            if ($R.properties.network.publicNetworkAccess -eq 'Enabled') { 'Public network access enabled' }
        }
    }
}
