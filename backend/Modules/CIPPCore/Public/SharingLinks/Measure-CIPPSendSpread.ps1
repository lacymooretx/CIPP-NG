function Measure-CIPPSendSpread {
    <#
    .SYNOPSIS
        Compares an account's last 24 hours of sent mail with its own previous week: how many outside recipients, and how many it has never written to.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-13). Pure function over message-trace rows
        (Get-CIPPBecMessageTrace: RecipientAddress, Received). A lateral-phishing account mails the lure to its whole
        address book, so the tell is a jump in DISTINCT external recipients - and most of them new - against the
        account's own baseline, not against a fixed number.

        Flagged when the last 24 hours reach at least MinNewRecipients external recipients the account did not mail
        in the baseline AND at least Factor times its average daily distinct external recipients (an average below 1
        counts as 1). Message trace keeps 10 days, so the baseline is the 7 days before the last 24 hours.
    .PARAMETER Rows
        Message-trace rows for one sender.
    .PARAMETER Now
        End of the measured day (UTC).
    .PARAMETER AcceptedDomains
        The tenant's accepted domains, lower case. Without them every recipient counts as external.
    .PARAMETER MinNewRecipients
        Minimum new external recipients in the last 24 hours (default 25).
    .PARAMETER Factor
        Minimum multiple of the baseline daily average (default 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [object[]]$Rows = @(),
        [datetime]$Now = (Get-Date).ToUniversalTime(),
        [string[]]$AcceptedDomains = @(),
        [int]$MinNewRecipients = 25,
        [double]$Factor = 3
    )

    $Accepted = @($AcceptedDomains | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $DayStart = $Now.AddHours(-24)
    $BaselineStart = $DayStart.AddDays(-7)
    $Recent = [System.Collections.Generic.HashSet[string]]::new()
    $Baseline = [System.Collections.Generic.HashSet[string]]::new()
    $PerDay = @{}
    foreach ($Row in @($Rows | Where-Object { $_ -and $_.RecipientAddress })) {
        $Recipient = ([string]$Row.RecipientAddress).Trim().ToLowerInvariant()
        if ($Accepted.Count -gt 0 -and $Accepted -contains ($Recipient -split '@')[-1]) { continue }
        $When = try { ([datetime]$Row.Received).ToUniversalTime() } catch { continue }
        if ($When -ge $DayStart -and $When -le $Now) {
            [void]$Recent.Add($Recipient)
        } elseif ($When -ge $BaselineStart -and $When -lt $DayStart) {
            [void]$Baseline.Add($Recipient)
            $Day = $When.ToString('yyyyMMdd')
            if (-not $PerDay.ContainsKey($Day)) { $PerDay[$Day] = [System.Collections.Generic.HashSet[string]]::new() }
            [void]$PerDay[$Day].Add($Recipient)
        }
    }
    $DailyAverage = [Math]::Round((@($PerDay.Values | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum / 7, 1)
    $New = @($Recent | Where-Object { -not $Baseline.Contains($_) })
    $Flagged = $New.Count -ge $MinNewRecipients -and $Recent.Count -ge ($Factor * [Math]::Max(1, $DailyAverage))

    [pscustomobject]@{
        Flagged                = [bool]$Flagged
        ExternalRecipients24h  = $Recent.Count
        NewExternalRecipients  = $New.Count
        BaselineDailyAverage   = $DailyAverage
        NewRecipientSample     = @($New | Select-Object -First 10)
        Summary                = "$($Recent.Count) external recipients in the last 24 h ($($New.Count) never mailed in the previous 7 days) against a daily average of $DailyAverage"
    }
}
