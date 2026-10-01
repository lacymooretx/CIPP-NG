function Invoke-CippTestAZ_DFC_12 {
    <#
    .SYNOPSIS
    Azure - Defender for Cloud secure score is at least 70%
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_DFC_12' -Name 'Defender for Cloud secure score is at least 70%' -Risk 'Medium' -Category 'Defender for Cloud' -UserImpact 'Low' -ImplementationEffort 'Medium' -Evaluate {
        param($Ctx)
        $Scores = @($Ctx.SecurityPosture | Where-Object { $_.itemKind -eq 'SecureScore' })
        if ($Scores.Count -eq 0) { return @{ Status = 'Skipped'; Markdown = 'No secure score available. Defender for Cloud is not active, or has not produced a score yet.' } }
        $Rows = $Scores | ForEach-Object { [ordered]@{ Subscription = $Ctx.SubName[[string]$_.subscriptionId] ?? $_.subscriptionId; Score = ('{0:N0}%' -f ([double]$_.percentage * 100)); Points = "$($_.currentScore) / $($_.maxScore)" } }
        $Min = ($Scores | Measure-Object -Property percentage -Minimum).Minimum
        $Status = if ($Min -ge 0.7) { 'Passed' } elseif ($Min -ge 0.5) { 'Investigate' } else { 'Failed' }
        @{ Status = $Status; Markdown = "Lowest subscription score: $('{0:N0}%' -f ($Min * 100)) (target 70%).`n`n$(Format-CippAzureFindingTable -Rows $Rows)" }
    }
}
