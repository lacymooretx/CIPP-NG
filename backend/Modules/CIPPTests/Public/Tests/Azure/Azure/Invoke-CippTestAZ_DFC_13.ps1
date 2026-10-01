function Invoke-CippTestAZ_DFC_13 {
    <#
    .SYNOPSIS
    Azure - No unresolved high-severity Defender for Cloud recommendations
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_13' -Name 'No unresolved high-severity Defender for Cloud recommendations' -Risk 'High' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        $Recs = @($Ctx.SecurityPosture | Where-Object { $_.itemKind -eq 'Recommendation' })
        $Scores = @($Ctx.SecurityPosture | Where-Object { $_.itemKind -eq 'SecureScore' })
        if ($Recs.Count -eq 0 -and $Scores.Count -eq 0) { return @{ Status = 'Skipped'; Markdown = 'No Defender for Cloud assessment data. Defender for Cloud is not active on the onboarded subscriptions.' } }
        $High = @($Recs | Where-Object { $_.severity -eq 'High' } | Sort-Object unhealthyCount -Descending)
        $Other = @($Recs | Where-Object { $_.severity -ne 'High' })
        if ($High.Count -eq 0) { return @{ Status = 'Passed'; Markdown = "No high-severity recommendations open. $($Other.Count) medium/low recommendation(s) open." } }
        $Rows = $High | ForEach-Object { [ordered]@{ Recommendation = $_.displayName; Subscription = $Ctx.SubName[[string]$_.subscriptionId] ?? $_.subscriptionId; 'Unhealthy resources' = $_.unhealthyCount } }
        @{ Status = 'Failed'; Markdown = "$($High.Count) high-severity recommendation(s) open ($($Other.Count) medium/low not shown):`n`n$(Format-CippAzureFindingTable -Rows $Rows)" }
    }
}
