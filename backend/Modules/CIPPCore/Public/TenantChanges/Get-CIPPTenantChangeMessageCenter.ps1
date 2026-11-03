function Get-CIPPTenantChangeMessageCenter {
    <#
    .SYNOPSIS
        Message Center posts that need attention today for one tenant: new or updated, or reaching a deadline milestone.
    .DESCRIPTION
        Read only, from the cached posts through Get-CIPPMessageCenterDigest, so the classification matches the digest
        page. A post counts when it is an alerting category (Notify) and new or updated in the window, or when its
        deadline reaches 30, 7 or 0 days left in the window. Every other post with a near deadline stays on the digest
        page, or it would repeat here every day for a month.

        The cache is nightly, so a post published just after one sync is first readable up to a day later. The
        new-or-updated window is therefore one day longer than asked: a post can show on two days, but cannot be missed
        between them. Nothing cached throws (-CacheOnly), so the caller can say "could not read".
        Aspendora fork addition (Vikunja CIPP-58).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Tenant,
        [int]$Days = 1,
        [int]$StaleDays = 3,
        [datetime]$Now = [datetime]::UtcNow
    )

    $Digest = Get-CIPPMessageCenterDigest -TenantFilter $Tenant -Days ($Days + 1) -DeadlineDays 30 -CacheOnly -Now $Now
    $Errors = @(@($Digest.Errors) | Where-Object { $_ })
    if ($Errors.Count -gt 0) { throw ($Errors -join ' ') }

    $Changes = [System.Collections.Generic.List[object]]::new()
    foreach ($Item in @($Digest.Items)) {
        if ($null -eq $Item) { continue }
        $DaysLeft = if ($null -eq $Item.DaysLeft -or [string]$Item.DaysLeft -eq '') { $null } else { [int]$Item.DaysLeft }

        $Milestone = $false
        if ($null -ne $DaysLeft) {
            foreach ($Mark in 30, 7, 0) {
                if ($DaysLeft -le $Mark -and $DaysLeft -gt ($Mark - $Days)) { $Milestone = $true }
            }
        }

        $Change = $null
        $WhenUtc = ''
        if ($Item.Notify -and $Item.WindowReason -eq 'New') {
            $Change = 'New post'
            $WhenUtc = [string]$Item.PublishedUtc
        } elseif ($Item.Notify -and $Item.WindowReason -eq 'Updated') {
            $Change = 'Updated post'
            $WhenUtc = [string]$Item.LastUpdatedUtc
        } elseif ($Milestone) {
            $Change = if ($DaysLeft -lt 0) { 'Deadline passed' } elseif ($DaysLeft -eq 0) { 'Deadline today' } elseif ($DaysLeft -eq 1) { 'Deadline in 1 day' } else { "Deadline in $DaysLeft days" }
        }
        if (-not $Change) { continue }

        $Deadline = if ($Item.Deadline) { " Deadline $($Item.Deadline)." } else { '' }
        $Changes.Add([pscustomobject]@{
                Source  = 'Message Center'
                Change  = $Change
                Risk    = ''
                Title   = "$($Item.MessageId): $($Item.Title)"
                Detail  = "$($Item.CategoryLabel).$Deadline"
                When    = $(if ($WhenUtc) { Format-CIPPCentralTime -Value $WhenUtc } else { [string]$Item.Deadline })
                WhenUtc = $WhenUtc
                Link    = [string]$Item.Link
            })
    }

    $CacheTime = ConvertTo-CIPPTenantChangeUtc -Value $Digest.Summary.OldestCacheUtc
    [pscustomobject]@{
        Status  = $(if (-not $CacheTime -or $CacheTime -lt $Now.AddDays(-$StaleDays)) { 'Stale' } else { 'OK' })
        Detail  = "$([int]$Digest.Summary.PostsRead) cached posts read, cached $(if ($CacheTime) { Format-CIPPCentralTime -Value $CacheTime } else { 'at an unreadable date' })."
        Changes = @($Changes)
    }
}
