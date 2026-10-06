function Invoke-CIPPMailboxItemImport {
    <#
    .SYNOPSIS
        Posts an item staged by Invoke-CIPPMailboxItemExport to a mailbox import session URL
    .DESCRIPTION
        Thin wrapper over [CIPP.CippMailboxTransfer]::Import so the copy activity can be tested with Mock.
        Returns a CIPP.MailboxImportResult (Success, StatusCode, Body, RetryAfterSeconds). Safe to call
        again on retry; the staged bytes are kept until the caller releases them.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Export,
        [Parameter(Mandatory = $true)][string]$ImportUrl,
        # Abandon the call after this many seconds (0 = client default); the caller passes its time budget.
        [int]$TimeoutSeconds = 0
    )
    [CIPP.CippMailboxTransfer]::Import($Export, $ImportUrl, $TimeoutSeconds)
}
