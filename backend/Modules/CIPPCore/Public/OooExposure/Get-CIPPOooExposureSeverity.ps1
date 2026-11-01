function Get-CIPPOooExposureSeverity {
    <#
    .SYNOPSIS
        Severity of an active auto-reply from its external audience and message flags.
    .DESCRIPTION
        High   - ExternalAudience All and the message names an internal address, a phone number or a finance cue:
                 anyone who emails the mailbox learns who to impersonate or who to call about payments.
        Medium - ExternalAudience All without those cues (still confirms the mailbox is live and the person away).
        Low    - ExternalAudience Known (only senders in the mailbox's contacts get the external reply).
        None   - ExternalAudience None: no external reply is sent.
        Aspendora fork addition (Vikunja CIPP-40).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$ExternalAudience,
        [string[]]$Flags = @()
    )
    switch ([string]$ExternalAudience) {
        'All' {
            if (@($Flags | Where-Object { $_ -in @('InternalEmail', 'Phone', 'Finance') }).Count -gt 0) { return 'High' }
            return 'Medium'
        }
        'Known' { return 'Low' }
        default { return 'None' }
    }
}
