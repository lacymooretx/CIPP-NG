function Get-CIPPAlertSharingBurst {
    <#
    .SYNOPSIS
        Alert on lateral OneDrive/SharePoint phishing and mass external sharing from a (likely compromised) account
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-13). Raises:
          UserBurst     one account shares with RecipientThreshold+ distinct external recipients within WindowMinutes
          FileSpread    one item reaches FileRecipientThreshold+ distinct external recipients over the lookback
          LinkMailBlast an account creates anyone/company/secure links and its sent mail jumps to SendSpreadThreshold+
                        new external recipients against its own previous week
        Each finding carries the preceding risky/unfamiliar sign-in (24 h before, when sign-in logs are licensed),
        the send-spread comparison and ready parameters for ExecRemoveSharingLink, ExecBulkRemoveSharingLinks and
        ExecSetOneDriveSharing. Detection only: nothing is remediated.

        High when the file is a typical lure (OneNote, PDF, HTML, SVG...), a notable sign-in preceded it, sent mail
        spiked, or it reached twice the threshold; Medium otherwise.

        Source is Search-UnifiedAuditLog over the lookback (see Get-CIPPSharingBurstReport for why not the Graph
        audit query API or the webhook stream). SharePoint audit events usually land within 30-90 minutes but can
        take longer, so the lookback overlaps runs and Write-AlertTrace -Append keeps one notification per stable Id
        (detection | account or item | day the sharing started).
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        [Parameter(Mandatory)]
        $TenantFilter
    )

    $IntOr = { param($Value, $Default) $Parsed = 0; if ([int]::TryParse([string]$Value, [ref]$Parsed) -and $Parsed -gt 0) { $Parsed } else { $Default } }
    $Params = @{
        TenantFilter           = $TenantFilter
        LookbackHours          = [Math]::Min((& $IntOr $InputValue.SharingBurstLookbackHours 24), 168)
        RecipientThreshold     = & $IntOr $InputValue.SharingBurstRecipients 25
        WindowMinutes          = & $IntOr $InputValue.SharingBurstWindowMinutes 60
        FileRecipientThreshold = & $IntOr $InputValue.SharingBurstFileRecipients 25
        SendSpreadThreshold    = & $IntOr $InputValue.SharingBurstSendSpread 25
        AllowList              = @(([string]$InputValue.SharingBurstAllowList) -split '[,;\s]+' | Where-Object { $_ })
    }
    $MaxSurfaced = & $IntOr $InputValue.SharingBurstMaxPerCycle 10

    try {
        $Report = Get-CIPPSharingBurstReport @Params
        foreach ($Message in @($Report.Errors)) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Sharing burst: $Message" -sev Warning
        }
        if (-not $Report.Complete) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Sharing burst: the audit-log search was incomplete ($($Report.Cap)); findings may be missing." -sev Warning
        }
        $Rows = @($Report.Findings | Select-Object -Property * -ExcludeProperty Remediation)
        if ($Rows.Count -eq 0) { return }

        $CmdletName = [string]$MyInvocation.MyCommand
        $New = @(Write-AlertTrace -cmdletName $CmdletName -tenantFilter $TenantFilter -data $Rows -Append | Where-Object { $_ })
        if ($New.Count -eq 0) { return }
        if ($New.Count -gt $MaxSurfaced) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Sharing burst: $($New.Count) new findings exceeded the per-run cap of $MaxSurfaced; surfaced the $MaxSurfaced most severe. The rest are recorded and will not re-surface." -sev Warning
        }
        $New | Sort-Object @{ Expression = { if ($_.Severity -eq 'High') { 0 } else { 1 } } }, @{ Expression = { [int]$_.ExternalRecipients }; Descending = $true } | Select-Object -First $MaxSurfaced
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Sharing burst alert failed for $($TenantFilter): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
    }
}
