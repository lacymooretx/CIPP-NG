function Get-CIPPMailboxQuotaRisk {
    <#
    .SYNOPSIS
        Classify mailboxes by genuine quota risk, separating it from stale warning quotas.
    .DESCRIPTION
        Using Microsoft's own issueWarningQuota was the original plan - it is the point the
        user actually starts seeing warnings, and it beats inventing a round percentage.
        Checked against production, it needs one guard.

        3E NDT has two mailboxes past their warning quota. Only one is in trouble:

          ken@3endt.com     47.13 GB used, warn 45 GB, hard 50 GB   -> 94% full, real
          Sameer@3endt.com  69.47 GB used, warn 45 GB, hard 100 GB  -> 69% full, 30 GB free

        Sameer's mailbox was moved to the 100 GB tier and issueWarningQuota was left behind
        at the 45 GB default. Ticketing on the warning quota alone would have raised a
        capacity ticket for a mailbox with 30 GB of headroom - exactly the false positive
        that trained everyone to ignore CIPP tickets last time.

        So risk is judged on the HARD quota, which cannot go stale, and the warning quota is
        used for a different and genuinely useful finding: Outlook is nagging Sameer daily
        about a mailbox that is fine. That is a configuration defect worth reporting, not a
        capacity one, and it should never create a ticket.

    .PARAMETER Mailboxes
        Rows from getMailboxUsageDetail.
    .PARAMETER RiskPercent
        Percentage of the hard quota at which a mailbox is genuinely at risk.
    .PARAMETER StaleWarningRatio
        A warning quota below this fraction of the hard quota is treated as not rescaled.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$Mailboxes,
        [int]$RiskPercent = 85,
        [double]$StaleWarningRatio = 0.8
    )

    $AtRisk = [System.Collections.Generic.List[object]]::new()
    $WarnedOnly = [System.Collections.Generic.List[object]]::new()
    $StaleWarning = [System.Collections.Generic.List[object]]::new()
    $Checked = 0

    foreach ($M in @($Mailboxes)) {
        if (-not $M -or -not $M.userPrincipalName) { continue }
        if ($M.isDeleted -eq $true) { continue }
        $Checked++

        $Used = 0L; $Warn = 0L; $Hard = 0L
        try { $Used = [long]($M.storageUsedInBytes ?? 0) } catch {}
        try { $Warn = [long]($M.issueWarningQuotaInBytes ?? 0) } catch {}
        try { $Hard = [long]($M.prohibitSendReceiveQuotaInBytes ?? 0) } catch {}
        if ($Used -le 0 -or $Hard -le 0) { continue }

        $Percent = [math]::Round(($Used / [double]$Hard) * 100, 1)
        $Record = [pscustomobject]@{
            Upn          = [string]$M.userPrincipalName
            DisplayName  = [string]$M.displayName
            UsedBytes    = $Used
            WarnBytes    = $Warn
            HardBytes    = $Hard
            PercentUsed  = $Percent
            ItemCount    = [long]($M.itemCount ?? 0)
            HasArchive   = [bool]$M.hasArchive
            RecipientType = [string]$M.recipientType
        }

        if ($Percent -ge $RiskPercent) {
            $AtRisk.Add($Record)
            continue
        }

        # Below the risk line, but Outlook is already warning the user.
        if ($Warn -gt 0 -and $Used -ge $Warn) {
            $WarnedOnly.Add($Record)
            if (($Warn / [double]$Hard) -lt $StaleWarningRatio) {
                $StaleWarning.Add($Record)
            }
        }
    }

    return [pscustomobject]@{
        Checked      = $Checked
        AtRisk       = @($AtRisk | Sort-Object -Property PercentUsed -Descending)
        WarnedOnly   = @($WarnedOnly | Sort-Object -Property PercentUsed -Descending)
        StaleWarning = @($StaleWarning | Sort-Object -Property PercentUsed -Descending)
    }
}
