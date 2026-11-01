function Get-CIPPPostureCurrent {
    <#
    .SYNOPSIS
        Build a compact posture snapshot for a tenant from data CIPP already stores.
    .DESCRIPTION
        Reads, without any live Graph call:
          - the latest CIPPTests results (ZTNA, CIS, EIDSCA, ORCA, CISA, E8, Azure, Custom, ...) from the
            CippTestResults table, written by the nightly test run;
          - the latest Microsoft Secure Score from the CIPP reporting DB cache, via Get-CIPPSecureScoreReport.
        Each test is trimmed to Id / Name / Suite / Category / Status / Risk. Status is normalised to
        Pass / Fail / Investigate / NA using the same buckets as ListTests (Active and Postponed count as Fail;
        Skipped, Informational and Unlicensed are NA because they say nothing about the tenant's configuration).
        Date is the US Central calendar day, which is the snapshot's RowKey. Aspendora fork addition (Vikunja CIPP-16).
    .PARAMETER TenantFilter
        Tenant default domain name or customerId.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    $Domain = $TenantFilter
    try {
        $Tenant = Get-Tenants -TenantFilter $TenantFilter -IncludeErrors | Select-Object -First 1
        if ($Tenant.defaultDomainName) { $Domain = [string]$Tenant.defaultDomainName }
    } catch {}

    $NowUtc = [datetime]::UtcNow
    $Central = try { [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch {
        try { [System.TimeZoneInfo]::FindSystemTimeZoneById('Central Standard Time') } catch { $null }
    }
    $NowCentral = if ($Central) { [System.TimeZoneInfo]::ConvertTimeFromUtc($NowUtc, $Central) } else { $NowUtc }

    # Suite from the test id, exactly as Get-CIPPTestResultsTenants labels it.
    $SuiteIdPatterns = [ordered]@{}
    foreach ($Entry in (Get-CippTestSuitePatterns).GetEnumerator()) {
        $SuiteIdPatterns[$Entry.Key] = $Entry.Value -replace '^Invoke-CippTest', ''
    }

    $Tests = [System.Collections.Generic.List[object]]::new()
    $Errors = [System.Collections.Generic.List[string]]::new()
    $Raw = @()
    try {
        $Table = Get-CippTable -tablename 'CippTestResults'
        $Raw = @(Get-CIPPAzDataTableEntity @Table -Filter ("PartitionKey eq '{0}'" -f $Domain))
    } catch {
        $Errors.Add("Test results could not be read: $($_.Exception.Message)")
    }
    $LastRun = $null
    foreach ($R in $Raw) {
        if (-not $R.RowKey) { continue }
        $Id = [string]$R.RowKey
        $Suite = ''
        if ($Id -like 'CustomScript-*') { $Suite = 'Custom' } else {
            foreach ($P in $SuiteIdPatterns.GetEnumerator()) { if ($Id -like $P.Value) { $Suite = $P.Key; break } }
        }
        $Status = switch ([string]$R.Status) {
            'Passed' { 'Pass' }
            { $_ -in @('Failed', 'Active', 'Postponed') } { 'Fail' }
            'Investigate' { 'Investigate' }
            default { 'NA' }
        }
        $Tests.Add([pscustomobject]@{
                Id       = $Id
                Name     = $(if ($R.Name) { [string]$R.Name } else { $Id })
                Suite    = $Suite
                Category = [string]$R.Category
                Status   = $Status
                Risk     = ([string]$R.Risk).Trim()
            })
        if ($R.Timestamp) {
            try {
                $Ts = ([datetimeoffset]$R.Timestamp).UtcDateTime
                if (-not $LastRun -or $Ts -gt $LastRun) { $LastRun = $Ts }
            } catch {}
        }
    }

    $Score = $null
    try {
        $Ss = @(Get-CIPPSecureScoreReport -TenantFilter $Domain) | Select-Object -First 1
        if ($Ss -and $null -ne $Ss.CurrentScore -and [double]$Ss.MaxScore -gt 0) {
            $SsDate = if ($Ss.CapturedAt -is [datetime]) { ([datetime]$Ss.CapturedAt).ToString('yyyy-MM-dd') } elseif ($Ss.CapturedAt) { ([string]$Ss.CapturedAt).Substring(0, [math]::Min(10, ([string]$Ss.CapturedAt).Length)) } else { '' }
            $Score = [pscustomobject]@{
                Current = [math]::Round([double]$Ss.CurrentScore, 2)
                Max     = [math]::Round([double]$Ss.MaxScore, 2)
                Percent = [math]::Round(100 * [double]$Ss.CurrentScore / [double]$Ss.MaxScore, 1)
                Date    = $SsDate
            }
        }
    } catch {
        $Errors.Add("Secure Score could not be read: $($_.Exception.Message)")
    }

    return [pscustomobject]@{
        Tenant       = $Domain
        Date         = $NowCentral.ToString('yyyy-MM-dd')
        CapturedAt   = $NowUtc.ToString('o')
        TestsLastRun = $(if ($LastRun) { $LastRun.ToString('o') } else { $null })
        SecureScore  = $Score
        Tests        = $Tests
        Errors       = $Errors
    }
}
