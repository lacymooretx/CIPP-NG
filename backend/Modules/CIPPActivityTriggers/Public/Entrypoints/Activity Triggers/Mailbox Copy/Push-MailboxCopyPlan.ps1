function Push-MailboxCopyPlan {
    <#
    .SYNOPSIS
        Lists a mailbox copy's source items into chunks, then starts the copy lanes (resumable)
    .DESCRIPTION
        Walks every folder row (f00001..) written by Start-CIPPMailboxCopy, pages its items oldest
        first and writes chunk rows (c00001..) of up to 100 item ids. Listing everything up front
        keeps the copy stable for Move: deleting copied items would otherwise shift the $skip
        paging of anything still being listed.

        Timeboxed: checkpoints folder index + skip on the operation row and requeues itself.
        Folder rows carry their own source/destination mailbox ids and API version (the online
        archive is a separate mailbox, reachable only through beta); chunk rows copy them.

        When done it starts three Sequential orchestrations (lanes) of Push-MailboxCopyChunk.
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param($Item)

    $OperationId = [string]$Item.OperationId
    $TenantFilter = [string]$Item.TenantFilter
    $ChunkSize = 100
    $Lanes = 3
    $TimeboxSeconds = 600
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $Table = Get-CippTable -tablename 'MailboxCopy'
    $Op = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Operation' and RowKey eq '$OperationId'"
    if (-not $Op -or $Op.Status -ne 'Planning') { return @() }

    $Folders = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$OperationId' and RowKey ge 'f' and RowKey lt 'g'" | Sort-Object RowKey)
    $FolderIndex = [int]($Op.PlanFolderIndex ?? 0)
    $Skip = [int]($Op.PlanSkip ?? 0)
    $ChunkCount = [int]($Op.ChunkCount ?? 0)
    $Listed = [int]($Op.ListedItems ?? 0)


    try {
        while ($FolderIndex -lt $Folders.Count) {
            $Folder = $Folders[$FolderIndex]
            # Each folder row names its own mailbox and API: archive folders live in a different mailbox
            # and are only reachable through beta. Rows from before archive support fall back to the op.
            $SrcMailboxId = [string]($Folder.SrcMailboxId ?? $Op.SrcMailboxId)
            $Base = "https://graph.microsoft.com/$([string]($Folder.SrcApi ?? 'v1.0'))/admin/exchange/mailboxes/$SrcMailboxId/folders"
            if ([int]$Folder.ItemCount -gt 0) {
                $Uri = "$Base/$($Folder.SrcFolderId)/items?`$select=id,size&`$orderby=createdDateTime&`$top=$ChunkSize&`$skip=$Skip"
                while ($true) {
                    $Page = @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -AsApp $true -noPagination $true)
                    $Ids = @($Page | Where-Object { $_.id } | ForEach-Object { "$($_.id)|$([int64]($_.size ?? 0))" })
                    if ($Ids.Count -gt 0) {
                        $ChunkCount++
                        Add-CIPPAzDataTableEntity @Table -Entity @{
                            PartitionKey = $OperationId
                            RowKey       = 'c{0:D5}' -f $ChunkCount
                            SrcMailboxId = $SrcMailboxId
                            DstMailboxId = [string]($Folder.DstMailboxId ?? $Op.DstMailboxId)
                            SrcApi       = [string]($Folder.SrcApi ?? 'v1.0')
                            DstApi       = [string]($Folder.DstApi ?? 'v1.0')
                            SrcFolderId  = [string]$Folder.SrcFolderId
                            DstFolderId  = [string]$Folder.DstFolderId
                            Path         = [string]$Folder.Path
                            Ids          = [string](ConvertTo-Json -InputObject @($Ids) -Compress)
                            Count        = $Ids.Count
                            Done         = 0
                            Copied       = 0
                            Failed       = 0
                            State        = 'Pending'
                        } -Force
                        $Listed += $Ids.Count
                    }
                    if ($Ids.Count -lt $ChunkSize) { break }
                    $Skip += $Ids.Count
                    $Uri = "$Base/$($Folder.SrcFolderId)/items?`$select=id,size&`$orderby=createdDateTime&`$top=$ChunkSize&`$skip=$Skip"
                    if ($Stopwatch.Elapsed.TotalSeconds -gt $TimeboxSeconds) {
                        $Op | Add-Member -NotePropertyName PlanFolderIndex -NotePropertyValue $FolderIndex -Force
                        $Op | Add-Member -NotePropertyName PlanSkip -NotePropertyValue $Skip -Force
                        $Op | Add-Member -NotePropertyName ChunkCount -NotePropertyValue $ChunkCount -Force
                        $Op | Add-Member -NotePropertyName ListedItems -NotePropertyValue $Listed -Force
                        Add-CIPPAzDataTableEntity @Table -Entity $Op -Force
                        $null = Start-CIPPOrchestrator -InputObject ([PSCustomObject]@{
                                OrchestratorName = "MailboxCopyPlanResume_$($OperationId.Substring(0, 8))_$([guid]::NewGuid().ToString('N').Substring(0, 6))"
                                Batch            = @([PSCustomObject]@{ FunctionName = 'MailboxCopyPlan'; OperationId = $OperationId; TenantFilter = $TenantFilter })
                                SkipLog          = $true
                            })
                        return @()
                    }
                }
            }
            $FolderIndex++
            $Skip = 0
        }
    } catch {
        $Message = Get-NormalizedError -message $_.Exception.Message
        $Op | Add-Member -NotePropertyName Status -NotePropertyValue 'Failed' -Force
        $Op | Add-Member -NotePropertyName Message -NotePropertyValue "Listing items failed in '$($Folders[$FolderIndex].Path)': $Message" -Force
        Add-CIPPAzDataTableEntity @Table -Entity $Op -Force
        Write-LogMessage -API 'MailboxCopy' -tenant $TenantFilter -message "Mailbox copy $OperationId planning failed: $Message" -sev Error
        return @()
    }

    $Op | Add-Member -NotePropertyName PlanFolderIndex -NotePropertyValue $FolderIndex -Force
    $Op | Add-Member -NotePropertyName ChunkCount -NotePropertyValue $ChunkCount -Force
    $Op | Add-Member -NotePropertyName ListedItems -NotePropertyValue $Listed -Force
    $Op | Add-Member -NotePropertyName Status -NotePropertyValue $(if ($ChunkCount -gt 0) { 'Copying' } else { 'Completed' }) -Force
    Add-CIPPAzDataTableEntity @Table -Entity $Op -Force
    if ($ChunkCount -eq 0) { return @() }

    for ($Lane = 0; $Lane -lt [Math]::Min($Lanes, $ChunkCount); $Lane++) {
        $Batch = for ($c = $Lane + 1; $c -le $ChunkCount; $c += $Lanes) {
            [PSCustomObject]@{ FunctionName = 'MailboxCopyChunk'; OperationId = $OperationId; TenantFilter = $TenantFilter; ChunkKey = ('c{0:D5}' -f $c) }
        }
        $null = Start-CIPPOrchestrator -InputObject ([PSCustomObject]@{
                OrchestratorName = "MailboxCopy_$($OperationId.Substring(0, 8))_lane$Lane"
                Batch            = @($Batch)
                Sequential       = $true
                SkipLog          = $true
            })
    }
    Write-LogMessage -API 'MailboxCopy' -tenant $TenantFilter -message "Mailbox copy ${OperationId}: listed $Listed items into $ChunkCount chunks; copying" -sev Info
    return @()
}
