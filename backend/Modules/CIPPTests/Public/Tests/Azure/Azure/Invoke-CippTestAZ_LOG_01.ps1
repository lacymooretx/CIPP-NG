function Invoke-CippTestAZ_LOG_01 {
    <#
    .SYNOPSIS
    Azure - Activity log is exported for retention
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_LOG_01' -Name 'Activity log is exported for retention' -Risk 'Medium' -Category 'Logging & Monitoring' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        Invoke-CippAzureSubscriptionCheck -Context $Ctx -FailStatus 'Failed' -Requirement 'a diagnostic setting exports Administrative and Security activity-log events' -Check {
            param($SubId)
            $A = $Ctx.ActivityLog[$SubId.ToLower()]
            if (-not $A) { return '#skip:activity-log settings not collected' }
            $Ok = @($A.settings | Where-Object {
                    ($_.workspaceId -or $_.storageAccountId -or $_.eventHubAuthorizationRuleId) -and
                    @($_.logs | Where-Object { $_.enabled -and $_.category -in @('Administrative', 'Security') }).Count -ge 2
                })
            if ($Ok.Count -eq 0) { 'Activity log is not exported (kept only 90 days in Azure)' }
        }
    }
}
