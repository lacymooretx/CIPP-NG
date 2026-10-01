function Invoke-CippTestAZ_GOV_02 {
    <#
    .SYNOPSIS
    Azure - Azure Policy compliance summary
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_GOV_02' -Name 'Azure Policy compliance summary' -Risk 'Informational' -Category 'Governance' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        $Rows = @($Ctx.Policy | Where-Object { [int]$_.nonCompliantResources -gt 0 } | Sort-Object { [int]$_.nonCompliantResources } -Descending | ForEach-Object {
                [ordered]@{ Assignment = $_.displayName ?? $_.name; Subscription = $Ctx.SubName[[string]$_.subscriptionId] ?? $_.scope; 'Non-compliant resources' = $_.nonCompliantResources; Enforcement = $_.enforcementMode }
            })
        if ($Rows.Count -eq 0) { return @{ Status = 'Passed'; Markdown = "$(@($Ctx.Policy).Count) policy assignment(s); no non-compliant resources reported." } }
        @{ Status = 'Informational'; Markdown = "$($Rows.Count) policy assignment(s) report non-compliant resources:`n`n$(Format-CippAzureFindingTable -Rows $Rows)" }
    }
}
