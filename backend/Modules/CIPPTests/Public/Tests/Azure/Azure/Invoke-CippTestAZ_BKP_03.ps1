function Invoke-CippTestAZ_BKP_03 {
    <#
    .SYNOPSIS
    Azure - Azure Backup jobs are succeeding
    #>
    param($Tenant)

    Invoke-CippAzureTest -Tenant $Tenant -TestId 'AZ_BKP_03' -Name 'Azure Backup jobs are succeeding' -Risk 'Medium' -Category 'Backup & Recovery' -UserImpact 'Low' -ImplementationEffort 'Low' -Evaluate {
        param($Ctx)
        $Items = @($Ctx.BackupItems)
        if ($Items.Count -eq 0) { return @{ Status = 'Skipped'; Markdown = 'No Azure Backup protected items.' } }
        $Bad = @($Items | Where-Object { $_.protectionState -in @('ProtectionError', 'ProtectionStopped') -or ($_.lastBackupStatus -and $_.lastBackupStatus -notin @('Completed', 'Healthy')) })
        if ($Bad.Count -eq 0) { return @{ Status = 'Passed'; Markdown = "All $($Items.Count) protected item(s) report a healthy last backup." } }
        $Rows = $Bad | ForEach-Object { [ordered]@{ Item = ([string]$_.sourceResourceId).Split('/')[-1]; Workload = $_.workloadType; State = $_.protectionState; 'Last backup' = $_.lastBackupStatus; 'Last backup time' = $_.lastBackupTime } }
        @{ Status = 'Failed'; Markdown = "$($Bad.Count) of $($Items.Count) protected item(s) are failing or stopped:`n`n$(Format-CippAzureFindingTable -Rows $Rows)" }
    }
}
