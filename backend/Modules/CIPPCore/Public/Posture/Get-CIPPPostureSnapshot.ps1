function Get-CIPPPostureSnapshot {
    <#
    .SYNOPSIS
        Read stored posture snapshots for a tenant.
    .DESCRIPTION
        Without -Date: returns the snapshot index (Date, CapturedAt, counts, Secure Score), oldest first, WITHOUT the
        test rows, so picking a baseline never downloads a year of blobs. With -Date: returns that one snapshot in
        the Get-CIPPPostureCurrent shape (Tests decoded), or $null if it does not exist.
        Aspendora fork addition (Vikunja CIPP-16).
    .PARAMETER TenantFilter
        Tenant default domain name (the PartitionKey).
    .PARAMETER Date
        The snapshot date (yyyy-MM-dd, US Central).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string]$Date
    )

    $Table = Get-CIPPTable -TableName 'CippPostureSnapshots'
    function ConvertTo-Score($Row) {
        if ($null -eq $Row.SecureScoreCurrent -or [double]$Row.SecureScoreMax -le 0) { return $null }
        [pscustomobject]@{ Current = [double]$Row.SecureScoreCurrent; Max = [double]$Row.SecureScoreMax; Percent = [double]$Row.SecureScorePercent; Date = [string]$Row.SecureScoreDate }
    }

    if (-not $Date) {
        $IndexProps = @('PartitionKey', 'RowKey', 'Date', 'CapturedAt', 'TestCount', 'PassCount', 'OpenCount', 'SecureScoreCurrent', 'SecureScoreMax', 'SecureScorePercent', 'SecureScoreDate')
        $Rows = @(Get-CIPPAzDataTableEntity @Table -Filter ("PartitionKey eq '{0}'" -f $TenantFilter) -Property $IndexProps)
        $Index = [System.Collections.Generic.List[object]]::new()
        foreach ($R in @($Rows | Where-Object { $_.RowKey } | Sort-Object -Property RowKey)) {
            $Index.Add([pscustomobject]@{
                    Date        = [string]$R.RowKey
                    CapturedAt  = [string]$R.CapturedAt
                    TestCount   = [int]$R.TestCount
                    PassCount   = [int]$R.PassCount
                    OpenCount   = [int]$R.OpenCount
                    SecureScore = (ConvertTo-Score $R)
                })
        }
        return , $Index
    }

    $Row = Get-CIPPAzDataTableEntity @Table -Filter ("PartitionKey eq '{0}' and RowKey eq '{1}'" -f $TenantFilter, $Date) | Select-Object -First 1
    if (-not $Row) { return $null }
    $Chunks = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt [int]$Row.DataParts; $i++) { $Chunks.Add([string]$Row."Data$i") }
    return [pscustomobject]@{
        Tenant      = $TenantFilter
        Date        = [string]$Row.RowKey
        CapturedAt  = [string]$Row.CapturedAt
        SecureScore = (ConvertTo-Score $Row)
        Tests       = (ConvertFrom-CIPPPostureBlob -Chunks $Chunks.ToArray())
    }
}
