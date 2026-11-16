function Push-StorageSnapshotCollect {
    <#
    .FUNCTIONALITY
        Entrypoint
    .SYNOPSIS
        One tenant's daily storage collection, queued by Start-StorageSnapshotTimer (Aspendora fork, CIPP-64).
    .DESCRIPTION
        Activity wrapper: the orchestrator hands an $Item, Push-CIPPStorageSnapshot takes -TenantFilter.
        Errors are logged per tenant so one failing client does not hide the others.
    #>
    param($Item)
    try {
        $Result = Push-CIPPStorageSnapshot -TenantFilter $Item.TenantFilter
        $Msg = "Storage snapshot $($Result.Status): $($Result.TrendRows) trend, $($Result.MailboxRows) mailbox, $($Result.SiteRows) site rows"
        if (@($Result.Errors).Count) { $Msg += "; errors: $(@($Result.Errors) -join '; ')" }
        Write-LogMessage -API 'StorageSnapshot' -tenant $Item.TenantFilter -message $Msg -Sev $(if (@($Result.Errors).Count) { 'Warning' } else { 'Info' })
    } catch {
        Write-LogMessage -API 'StorageSnapshot' -tenant $Item.TenantFilter -message "Storage snapshot failed: $($_.Exception.Message)" -Sev 'Error' -LogData (Get-CippException -Exception $_)
    }
}
