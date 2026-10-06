function Invoke-CIPPMailboxItemExport {
    <#
    .SYNOPSIS
        Exports one mailbox item as bytes, staged for import into a folder ([CIPP.CippMailboxTransfer])
    .DESCRIPTION
        Thin wrapper so the copy activity can be tested with Mock; see CippMailboxTransfer.cs for why the
        item never becomes a PowerShell string. Returns a CIPP.MailboxExport (HasData, StatusCode, Body,
        RetryAfterSeconds, DataLength; Release() frees the bytes).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ExportUri,
        [Parameter(Mandatory = $true)][string]$Authorization,
        [Parameter(Mandatory = $true)][string]$ItemId,
        [Parameter(Mandatory = $true)][string]$FolderId,
        # Abandon the call after this many seconds (0 = client default); the caller passes its time budget.
        [int]$TimeoutSeconds = 0
    )
    [CIPP.CippMailboxTransfer]::Export($ExportUri, $Authorization, $ItemId, $FolderId, $TimeoutSeconds)
}
