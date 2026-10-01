function Invoke-CippTestAZ_SQL_03 {
    <#
    .SYNOPSIS
    Azure - Azure SQL has a Microsoft Entra administrator
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_SQL_03' -Name 'Azure SQL has a Microsoft Entra administrator' -Risk 'Medium' -Category 'Databases' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.sql/servers') -FailStatus 'Failed' -Requirement 'Entra ID administrator configured' -Check {
            param($R)
            if ($R.properties.administrators.administratorType -ne 'ActiveDirectory') { 'No Microsoft Entra administrator' }
        }
    }
}
