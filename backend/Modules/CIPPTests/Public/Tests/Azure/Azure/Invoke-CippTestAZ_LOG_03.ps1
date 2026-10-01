function Invoke-CippTestAZ_LOG_03 {
    <#
    .SYNOPSIS
    Azure - Log Analytics workspaces retain data at least 90 days
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_LOG_03' -Name 'Log Analytics workspaces retain data at least 90 days' -Risk 'Low' -Category 'Logging & Monitoring' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureResourceCheck -Context $Ctx -Type @('microsoft.operationalinsights/workspaces') -FailStatus 'Failed' -Requirement 'retention of 90 days or more' -Check {
            param($R)
            if ([int]$R.properties.retentionInDays -lt 90) { "Retention $($R.properties.retentionInDays) days" }
        }
    }
}
