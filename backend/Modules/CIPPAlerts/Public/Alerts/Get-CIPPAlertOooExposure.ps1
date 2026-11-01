function Get-CIPPAlertOooExposure {
    <#
    .SYNOPSIS
        Alert on external out-of-office replies that hand senders a colleague to impersonate, a phone number or payment cues
    .DESCRIPTION
        Uses Get-CIPPOooExposure (two EXO bulk requests per tenant) and raises mailboxes whose auto-reply is live for
        external senders right now. By default only High: ExternalAudience All and the message names a colleague
        (accepted-domain) address, a phone number or a finance cue (invoices, payments, wires, payroll...). Switch
        OooExposureIncludeMedium also raises every other All-audience reply. Known-audience replies are never raised.
        State mode, Id = 'OooExposure|<mailbox>|<start UTC>|<end UTC>' for Scheduled replies and
        'OooExposure|<mailbox>|enabled' for Enabled ones, so each out-of-office period notifies once and a new
        schedule notifies again. The alert never carries the message body: only the flags and a snippet with
        addresses and phone numbers masked. Fix from Email > Reports > Out-of-office Exposure. Report only.
        Tenants without Exchange Online are skipped silently; a run where no auto-reply settings could be read does
        not report, so open alerts are not resolved by a failed read. Aspendora fork addition (Vikunja CIPP-40).
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
    $IncludeMedium = (ConvertTo-CIPPBoolean $InputValue.OooExposureIncludeMedium) -eq $true
    $Severities = if ($IncludeMedium) { @('High', 'Medium') } else { @('High') }
    try {
        $Report = Get-CIPPOooExposure -TenantFilter $TenantFilter
    } catch {
        $Err = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Out-of-office exposure check failed: $($Err.NormalizedError)" -sev (Get-CIPPAlertFailureSeverity -ErrorText "$($Err.NormalizedError) $_") -LogData $Err
        return
    }
    if ($Report.Status -eq 'NoExchange') { return }
    if ($Report.MailboxesChecked -gt 0 -and $Report.SettingsRead -eq 0) {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Out-of-office exposure check could not read any auto-reply settings: $(@($Report.Errors) -join '; ')" -sev Warning
        return
    }
    $Rows = foreach ($Row in @($Report.Rows | Where-Object { $_.Severity -in $Severities -and $_.Window -eq 'Active' })) {
        $Period = if ($Row.AutoReplyState -eq 'Scheduled' -and $Row.StartTime -and $Row.EndTime) { "$($Row.StartTime)|$($Row.EndTime)" } else { 'enabled' }
        $Until = if ($Row.AutoReplyState -eq 'Scheduled') { "scheduled $($Row.StartCentral) to $($Row.EndCentral)" } else { 'enabled with no end date' }
        # No UserPrincipalName key: Get-AlertContentHash would key on it and ignore the per-period Id.
        [pscustomobject]@{
            Id               = "OooExposure|$(([string]$Row.Mailbox).ToLowerInvariant())|$Period"
            Mailbox          = $Row.Mailbox
            DisplayName      = $Row.DisplayName
            Severity         = $Row.Severity
            ExternalAudience = $Row.ExternalAudience
            AutoReplyState   = $Row.AutoReplyState
            Start            = $Row.StartCentral
            End              = $Row.EndCentral
            Flags            = $Row.FlagsText
            Snippet          = $Row.Snippet
            Message          = "$($Row.DisplayName) ($($Row.Mailbox)) sends an out-of-office reply to every external sender ($Until). $(if ($Row.Reasons) { "The external message $($Row.Reasons)." } else { "The external message has no contact or payment cues, but still confirms the mailbox is live and the person away." }) Attackers use this for payment fraud: limit external replies to known senders on Email > Reports > Out-of-office Exposure, and take colleague addresses, phone numbers and payment instructions out of the external message."
        }
    }
    Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows)
}
