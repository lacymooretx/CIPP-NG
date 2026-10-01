function Invoke-CippTestAZ_SQL_01 {
    <#
    .SYNOPSIS
    Azure - Azure SQL auditing is enabled
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_SQL_01' -Name 'Azure SQL auditing is enabled' -Risk 'Medium' -Category 'Databases' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.sql/servers') -FailStatus 'Failed' -Requirement 'server-level auditing enabled' -Check {
            param($R)
            $C = $Ctx.Config[([string]$R.id).ToLower()]
            if (-not $C -or $C.errors.auditingSettings) { return '#skip:auditing settings unavailable' }
            if ($C.config.auditingSettings.properties.state -ne 'Enabled') { 'Auditing disabled' }
        }
    }
}
