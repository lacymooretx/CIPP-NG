function Get-CIPPTenantChangeAlerts {
    <#
    .SYNOPSIS
        Alert items that became new, reopened or resolved for one tenant inside the window.
    .DESCRIPTION
        Read only. Reads the tenant's AlertLifecycle rows, which Write-AlertTrace maintains. That function resets
        FirstSeen when a resolved item comes back and raises ReopenCount, so a recent FirstSeen with a ReopenCount
        above zero is a reopen, and with zero is a new item. Only named fields leave this function, never the raw alert
        item.

        A hidden snooze keeps the item off the list but is counted. An Open row that has not been seen for more than
        StaleDays is not a change, but its age is reported, because that row may no longer be live.

        Zero rows is NotComparable with null counts, not OK: the table keeps 90 days, so an empty partition more likely means no alerts
        run for this tenant than that nothing happened. A read failure throws, so the caller can say "could not read".
        Aspendora fork addition (Vikunja CIPP-58).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Tenant,
        [int]$Days = 1,
        [int]$StaleDays = 7,
        [datetime]$Now = [datetime]::UtcNow
    )

    $Cutoff = $Now.AddDays(-$Days)
    $StaleCutoff = $Now.AddDays(-$StaleDays)

    $Table = Get-CIPPTable -tablename 'AlertLifecycle'
    $SafeTenant = ConvertTo-CIPPODataFilterValue -Value $Tenant -Type String
    # The table reader reports a failure as a non-terminating error and returns nothing, which would read as "no alerts".
    $Rows = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$SafeTenant'" -ErrorAction Stop | Where-Object { $null -ne $_ })

    if ($Rows.Count -eq 0) {
        return [pscustomobject]@{
            Status    = 'NotComparable'
            Detail    = 'No tracked alert items for this tenant in the last 90 days, so alerts may not be running here.'
            Changes   = @()
            New       = $null
            Reopened  = $null
            Resolved  = $null
            Snoozed   = $null
            StaleOpen = $null
            Undated   = $null
        }
    }

    $Changes = [System.Collections.Generic.List[object]]::new()
    $Snoozed = 0
    $StaleOpen = 0
    $Undated = 0
    $OldestStale = $null

    foreach ($Row in $Rows) {
        $Status = [string]$Row.Status
        $Name = ([string]$Row.CmdletName -replace '^Get-CIPPAlert', '') -creplace '(?<=[a-z0-9])(?=[A-Z])', ' '
        $Reopens = [int]($Row.ReopenCount ?? 0)

        if ($Status -eq 'Resolved') {
            $When = ConvertTo-CIPPTenantChangeUtc -Value $Row.ResolvedAt
            if (-not $When) { $Undated++; continue }
            if ($When -lt $Cutoff) { continue }
            $Change = 'Resolved'
        } else {
            # An item that was never seen resolving or arriving cannot be placed in the window, so it is counted, not dropped.
            $When = ConvertTo-CIPPTenantChangeUtc -Value $Row.FirstSeen
            if (-not $When) { $Undated++ }

            $LastSeen = ConvertTo-CIPPTenantChangeUtc -Value $Row.LastSeen
            if ($Status -eq 'Open' -and $LastSeen -and $LastSeen -lt $StaleCutoff) {
                $StaleOpen++
                if (-not $OldestStale -or $LastSeen -lt $OldestStale) { $OldestStale = $LastSeen }
            }

            if (-not $When -or $When -lt $Cutoff) { continue }
            if ($Status -eq 'Snoozed' -and [string]$Row.SnoozeVisible -ne 'True') { $Snoozed++; continue }
            $Change = if ($Reopens -gt 0) { 'Reopened' } else { 'New' }
        }

        $Changes.Add([pscustomobject]@{
                Source  = 'Alerts'
                Change  = $Change
                Risk    = ''
                Title   = $Name
                Detail  = [string]$Row.ContentPreview
                When    = Format-CIPPCentralTime -Value $When
                WhenUtc = $When.ToString('o')
                Link    = ''
            })
    }

    $Sorted = @($Changes | Sort-Object -Property WhenUtc -Descending)
    $Notes = [System.Collections.Generic.List[string]]::new()
    $Notes.Add("$($Rows.Count) tracked alert items read.")
    if ($Snoozed -gt 0) { $Notes.Add("$Snoozed new items are snoozed and not listed.") }
    if ($StaleOpen -gt 0) { $Notes.Add("$StaleOpen open items not seen for over $StaleDays days, the oldest last seen $(Format-CIPPCentralTime -Value $OldestStale).") }
    if ($Undated -gt 0) { $Notes.Add("$Undated items have no readable date and could not be placed in the window.") }

    [pscustomobject]@{
        # An undated item could be a change this record cannot see, so the tenant cannot be called quiet.
        Status    = $(if ($Undated -gt 0) { 'NotComparable' } else { 'OK' })
        Detail    = ($Notes -join ' ')
        Changes   = $Sorted
        New       = @($Sorted | Where-Object { $_.Change -eq 'New' }).Count
        Reopened  = @($Sorted | Where-Object { $_.Change -eq 'Reopened' }).Count
        Resolved  = @($Sorted | Where-Object { $_.Change -eq 'Resolved' }).Count
        Snoozed   = $Snoozed
        StaleOpen = $StaleOpen
        Undated   = $Undated
    }
}
