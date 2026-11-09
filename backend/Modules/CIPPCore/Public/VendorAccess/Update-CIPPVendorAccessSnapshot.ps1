function Update-CIPPVendorAccessSnapshot {
    <#
    .SYNOPSIS
        Builds the Vendor Access report for one tenant or all tenants and saves it to the CippVendorAccess table.
    .DESCRIPTION
        For each tenant: runs Get-CIPPVendorAccessReport, then compares the result with the saved snapshot.
        - An item seen for the first time gets FirstSeen = now. On a tenant's first run every item is marked Baseline,
          so the first email does not report the whole estate as new access.
        - An item in the saved snapshot but missing now is kept with Removed = true and RemovedAt, so the weekly
          email can say what went away. Removed rows are purged after 30 days.
        A tenant whose report fails keeps its previous snapshot; the failure is recorded on its Run row.
        Returns the snapshot as Get-CIPPVendorAccessSnapshot does. Aspendora fork addition (Vendor Access).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [string]$TenantFilter = 'AllTenants',
        [int]$StaleDays = 45
    )

    $Table = Get-CIPPTable -TableName 'CippVendorAccess'
    $Tenants = if ($TenantFilter -eq 'AllTenants') { @(Get-Tenants) } else { @(Get-Tenants -TenantFilter $TenantFilter) }
    $Now = [datetime]::UtcNow
    $Sha = [System.Security.Cryptography.SHA1]::Create()
    $KeyHash = { param($Key) ([System.BitConverter]::ToString($Sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key.ToLowerInvariant())))).Replace('-', '') }
    $Trim = { param($Text, $Max) $T = [string]$Text; if ($T.Length -gt $Max) { $T.Substring(0, $Max) + ' …' } else { $T } }

    foreach ($T in $Tenants) {
        $Domain = [string]$T.defaultDomainName
        if (-not $Domain) { continue }
        $Pk = $Domain.ToLowerInvariant()
        $Previous = @{}
        try { foreach ($Row in @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$Pk'")) { $Previous[[string]$Row.RowKey] = $Row } } catch {}
        $PreviousRun = try { Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Run' and RowKey eq '$Pk'" } catch { $null }
        $FirstRun = -not $PreviousRun -or -not $PreviousRun.GeneratedAt

        try {
            $Report = Get-CIPPVendorAccessReport -TenantFilter $Domain -StaleDays $StaleDays
        } catch {
            $Message = try { (Get-CippException -Exception $_).NormalizedError } catch { $_.Exception.Message }
            Write-LogMessage -API 'VendorAccess' -tenant $Domain -message "Vendor access report failed: $Message" -Sev 'Error'
            $RunRow = @{ PartitionKey = 'Run'; RowKey = $Pk; TenantName = [string]$T.displayName; LastError = [string]$Message; LastErrorAt = $Now; GeneratedAt = $PreviousRun.GeneratedAt; Errors = (ConvertTo-Json -InputObject @("Report failed: $Message") -Compress) }
            if (-not $RunRow.GeneratedAt) { $RunRow.Remove('GeneratedAt') }
            Add-CIPPAzDataTableEntity @Table -Entity $RunRow -Force | Out-Null
            continue
        }

        $Seen = [System.Collections.Generic.HashSet[string]]::new()
        $Entities = [System.Collections.Generic.List[object]]::new()
        foreach ($Item in $Report.Items) {
            $Rk = & $KeyHash ([string]$Item.Key)
            [void]$Seen.Add($Rk)
            $Old = $Previous[$Rk]
            $FirstSeen = if ($Old -and $Old.FirstSeen -and -not $Old.Removed) { ([datetimeoffset]$Old.FirstSeen).UtcDateTime } else { $Now }
            $Baseline = if ($Old -and -not $Old.Removed) { [bool]$Old.Baseline } else { [bool]$FirstRun }
            $Data = [ordered]@{}
            foreach ($P in $Item.PSObject.Properties) { $Data[$P.Name] = $P.Value }
            $Data.Access = & $Trim $Item.Access 10000
            $Data.RiskReasons = @($Item.RiskReasons | ForEach-Object { & $Trim $_ 400 } | Select-Object -First 20)
            $Json = ConvertTo-Json -InputObject $Data -Compress -Depth 5
            $Entities.Add(@{
                    PartitionKey = $Pk
                    RowKey       = $Rk
                    Key          = [string]$Item.Key
                    Kind         = [string]$Item.Kind
                    Risk         = [string]$Item.Risk
                    Stale        = [string]$Item.Stale
                    FirstSeen    = $FirstSeen
                    LastSeen     = $Now
                    Baseline     = $Baseline
                    Removed      = $false
                    Data         = $Json
                })
        }
        foreach ($Rk in $Previous.Keys) {
            if ($Seen.Contains($Rk)) { continue }
            $Old = $Previous[$Rk]
            if ($Old.Removed) {
                if ($Old.RemovedAt -and ([datetimeoffset]$Old.RemovedAt).UtcDateTime -lt $Now.AddDays(-30)) {
                    Remove-CIPPAzDataTableEntity @Table -Entity ($Old | Select-Object PartitionKey, RowKey, ETag) -Force | Out-Null
                }
                continue
            }
            $Entities.Add(@{
                    PartitionKey = $Pk
                    RowKey       = $Rk
                    Key          = [string]$Old.Key
                    Kind         = [string]$Old.Kind
                    Risk         = [string]$Old.Risk
                    Stale        = [string]$Old.Stale
                    FirstSeen    = ([datetimeoffset]$Old.FirstSeen).UtcDateTime
                    LastSeen     = ([datetimeoffset]$Old.LastSeen).UtcDateTime
                    Baseline     = [bool]$Old.Baseline
                    Removed      = $true
                    RemovedAt    = $Now
                    Data         = [string]$Old.Data
                })
        }
        foreach ($E in $Entities) { Add-CIPPAzDataTableEntity @Table -Entity $E -Force | Out-Null }
        Add-CIPPAzDataTableEntity @Table -Entity @{
            PartitionKey            = 'Run'
            RowKey                  = $Pk
            TenantName              = [string]$Report.TenantName
            TenantId                = [string]$Report.TenantId
            GeneratedAt             = $Now
            Source                  = [string]$Report.Source
            SignInActivityAvailable = [bool]$Report.SignInActivityAvailable
            FirstRunAt              = if ($FirstRun -or -not $PreviousRun.FirstRunAt) { $Now } else { ([datetimeoffset]$PreviousRun.FirstRunAt).UtcDateTime }
            Errors                  = (ConvertTo-Json -InputObject @($Report.Errors) -Compress)
            LastError               = ''
        } -Force | Out-Null
    }
    $Sha.Dispose()
    return Get-CIPPVendorAccessSnapshot -TenantFilter $TenantFilter
}
