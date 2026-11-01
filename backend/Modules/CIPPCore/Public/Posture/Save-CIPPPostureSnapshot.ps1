function Save-CIPPPostureSnapshot {
    <#
    .SYNOPSIS
        Store a posture snapshot (from Get-CIPPPostureCurrent) in the CippPostureSnapshots table.
    .DESCRIPTION
        PartitionKey = tenant default domain, RowKey = the US Central date (yyyy-MM-dd), so a second capture on the
        same day replaces the first instead of piling up rows. Summary numbers (test, open, pass counts and Secure
        Score) are plain properties so the snapshot index can be read without the test blob; the trimmed test rows
        are gzip + base64 chunks in Data0..DataN (ConvertTo-CIPPPostureBlob) with DataParts recording how many.

        A snapshot with no test results is NOT stored: tests that have not run yet (new tenant, failed nightly run)
        would otherwise become the baseline and next month every check would look "new". Snapshots older than
        RetainDays (default 400, a little over a year so a year-on-year comparison stays possible) are pruned.
        Aspendora fork addition (Vikunja CIPP-16).
    .PARAMETER Snapshot
        The object returned by Get-CIPPPostureCurrent.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Snapshot,
        [int]$RetainDays = 400
    )

    $Tests = @($Snapshot.Tests)
    if ($Tests.Count -eq 0) {
        Write-Information "Posture snapshot for $($Snapshot.Tenant) skipped: no CIPPTests results stored yet."
        return $false
    }

    $Chunks = ConvertTo-CIPPPostureBlob -Tests $Tests
    $Entity = @{
        PartitionKey = [string]$Snapshot.Tenant
        RowKey       = [string]$Snapshot.Date
        Date         = [string]$Snapshot.Date
        CapturedAt   = [string]$Snapshot.CapturedAt
        TestsLastRun = $(if ($Snapshot.TestsLastRun) { [string]$Snapshot.TestsLastRun } else { '' })
        Format       = 'gzip-json-v1'
        DataParts    = [int]$Chunks.Count
        TestCount    = [int]$Tests.Count
        PassCount    = [int]@($Tests | Where-Object { $_.Status -eq 'Pass' }).Count
        OpenCount    = [int]@($Tests | Where-Object { $_.Status -in @('Fail', 'Investigate') }).Count
    }
    for ($i = 0; $i -lt $Chunks.Count; $i++) { $Entity["Data$i"] = [string]$Chunks[$i] }
    if ($Snapshot.SecureScore) {
        $Entity['SecureScoreCurrent'] = [double]$Snapshot.SecureScore.Current
        $Entity['SecureScoreMax'] = [double]$Snapshot.SecureScore.Max
        $Entity['SecureScorePercent'] = [double]$Snapshot.SecureScore.Percent
        $Entity['SecureScoreDate'] = [string]$Snapshot.SecureScore.Date
    }

    $Table = Get-CIPPTable -TableName 'CippPostureSnapshots'
    # Replace, not merge: a smaller snapshot must not keep a stale Data3 from an earlier, larger one the same day.
    Add-CIPPAzDataTableEntity @Table -Entity $Entity -OperationType UpsertReplace | Out-Null

    try {
        $Cutoff = ([datetime]::UtcNow.AddDays(-$RetainDays)).ToString('yyyy-MM-dd')
        $Old = @(Get-CIPPAzDataTableEntity @Table -Filter ("PartitionKey eq '{0}' and RowKey lt '{1}'" -f $Snapshot.Tenant, $Cutoff) -Property @('PartitionKey', 'RowKey', 'ETag'))
        if ($Old.Count -gt 0) { Remove-AzDataTableEntity @Table -Entity $Old -Force | Out-Null }
    } catch {
        Write-Information "Posture snapshot pruning for $($Snapshot.Tenant) failed: $($_.Exception.Message)"
    }
    return $true
}
