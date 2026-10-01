function Invoke-CippTestAZ_LOG_02 {
    <#
    .SYNOPSIS
    Azure - Activity log alerts exist for critical changes
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_LOG_02' -Name 'Activity log alerts exist for critical changes' -Risk 'Medium' -Category 'Logging & Monitoring' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        Invoke-CippAzureSubscriptionCheck -Context $Ctx -FailStatus 'Failed' -Requirement 'activity-log alerts cover policy, NSG, security-solution, SQL-firewall and public-IP changes' -Check {
            param($SubId)
            $Required = @(
                'microsoft.authorization/policyassignments/write', 'microsoft.authorization/policyassignments/delete',
                'microsoft.network/networksecuritygroups/write', 'microsoft.network/networksecuritygroups/delete',
                'microsoft.network/networksecuritygroups/securityrules/write', 'microsoft.network/networksecuritygroups/securityrules/delete',
                'microsoft.security/securitysolutions/write', 'microsoft.security/securitysolutions/delete',
                'microsoft.sql/servers/firewallrules/write', 'microsoft.sql/servers/firewallrules/delete',
                'microsoft.network/publicipaddresses/write', 'microsoft.network/publicipaddresses/delete'
            )
            $Covered = @(Get-CippAzureResourcesOfType -Context $Ctx -Type 'microsoft.insights/activitylogalerts' | Where-Object {
                    $_.properties.enabled -ne $false -and @($_.properties.scopes | Where-Object { ([string]$_).ToLower() -like "/subscriptions/$($SubId.ToLower())*" }).Count
                } | ForEach-Object { $_.properties.condition.allOf } | Where-Object { $_.field -eq 'operationName' } | ForEach-Object { ([string]$_.equals).ToLower() })
            $Missing = @($Required | Where-Object { $Covered -notcontains $_ })
            if ($Missing.Count) { "$($Missing.Count) of $($Required.Count) operations have no alert: $(($Missing | ForEach-Object { $_ -replace '^microsoft\.', '' }) -join ', ')" }
        }
    }
}
