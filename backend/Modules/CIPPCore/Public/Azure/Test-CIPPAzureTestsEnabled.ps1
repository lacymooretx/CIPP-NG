function Test-CIPPAzureTestsEnabled {
    <#
    .SYNOPSIS
        Should the Azure (AZ_) test suite run for this tenant?
    .DESCRIPTION
        True when the last Azure collection found at least one readable subscription. When it
        didn't, any AZ_ results left from an earlier run (before a Reader grant was removed) are
        deleted, so the Azure tab never shows stale findings for a tenant CIPP can no longer see.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$TenantFilter)

    $Db = Get-CippTable -tablename 'CippReportingDB'
    $CountRow = Get-CIPPAzDataTableEntity @Db -Filter "PartitionKey eq '$TenantFilter' and RowKey eq 'AzureSubscriptions-Count'"
    if ([int]$CountRow.DataCount -gt 0) { return $true }

    try {
        $Results = Get-CippTable -tablename 'CippTestResults'
        # 'AZ`' is the first key after every 'AZ_…' key ('`' sorts directly after '_').
        $Stale = Get-CIPPAzDataTableEntity @Results -Filter "PartitionKey eq '$TenantFilter' and RowKey ge 'AZ_' and RowKey lt 'AZ``'" -Property PartitionKey, RowKey, ETag
        if ($Stale) {
            Remove-CIPPAzDataTableEntity @Results -Entity @($Stale) -Force
            Write-LogMessage -API 'Tests' -tenant $TenantFilter -message "Removed $(@($Stale).Count) stale Azure test result(s): no readable Azure subscription" -sev Info
        }
    } catch {
        Write-LogMessage -API 'Tests' -tenant $TenantFilter -message "Could not clear stale Azure test results: $($_.Exception.Message)" -sev Warning
    }
    $false
}
