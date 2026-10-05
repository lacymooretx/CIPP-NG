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

        Dedupe mode (the operation's Dedupe flag, set by ExecMailboxCopy Action=Resume): before listing a
        folder it reads the destination folder's PR_SEARCH_KEY values (Binary 0x300B) and leaves out
        every source item already there. FTS import keeps PR_SEARCH_KEY (verified: 100/100 copied
        calendar items matched their source), while createdDateTime and size both change - so this is
        the only reliable "already copied" test. Binary properties cannot be $filter'ed, hence one
        listing per destination folder rather than a lookup per item. Items without a search key are
        always copied.

        When done it starts Sequential orchestrations (lanes) of Push-MailboxCopyChunk over the chunks
        written by this planning pass (a resume numbers on from the earlier chunks): two lanes per
        destination mailbox, because Exchange's import throttle (IncomingBytes) is per mailbox.
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param($Item)

    $OperationId = [string]$Item.OperationId
    $TenantFilter = [string]$Item.TenantFilter
    $ChunkSize = 100
    # Lanes per destination mailbox. Exchange caps imports at ~150 MB per 5 minutes per mailbox per app
    # ("Application is over its IncomingBytes limit") and allows 4 concurrent requests per mailbox. Two
    # lanes keep one mailbox's budget full; a main mailbox and its online archive are separate mailboxes
    # with separate budgets, so each gets its own lanes and both fill at once.
    $LanesPerMailbox = 2
    $TimeboxSeconds = 600
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $Table = Get-CippTable -tablename 'MailboxCopy'
    $Op = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Operation' and RowKey eq '$OperationId'"
    if (-not $Op -or $Op.Status -ne 'Planning') { return @() }

    $Folders = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$OperationId' and RowKey ge 'f' and RowKey lt 'g'" | Sort-Object RowKey)
    $FolderIndex = [int]($Op.PlanFolderIndex ?? 0)
    $Skip = [int]($Op.PlanSkip ?? 0)
    $ChunkCount = [int]($Op.ChunkCount ?? 0)
    $FirstChunk = [int]($Op.PlanFirstChunk ?? 0)
    $Listed = [int]($Op.ListedItems ?? 0)
    $Dedupe = [bool]($Op.Dedupe ?? $false)
    $AlreadyPresent = [int]($Op.AlreadyPresent ?? 0)
    $KeyExpand = "`$expand=singleValueExtendedProperties(`$filter=id eq 'Binary 0x300B')"
    $SearchKey = {
        param($Entry)
        ($Entry.singleValueExtendedProperties | Where-Object { $_.id -match '0x300B' } | Select-Object -First 1).value
    }
    $Buffer = [System.Collections.Generic.List[string]]::new()
    $FlushChunk = {
        param($Folder, $SrcMailboxId)
        if ($Buffer.Count -eq 0) { return 0 }
        $Ids = @($Buffer)
        $Buffer.Clear()
        $null = Add-CIPPAzDataTableEntity @Table -Entity @{
            PartitionKey = $OperationId
            RowKey       = 'c{0:D5}' -f ($ChunkCount + 1)
            SrcMailboxId = $SrcMailboxId
            DstMailboxId = [string]($Folder.DstMailboxId ?? $Op.DstMailboxId)
            SrcApi       = [string]($Folder.SrcApi ?? 'v1.0')
            DstApi       = [string]($Folder.DstApi ?? 'v1.0')
            SrcFolderId  = [string]$Folder.SrcFolderId
            DstFolderId  = [string]$Folder.DstFolderId
            Path         = [string]$Folder.Path
            Ids          = [string](ConvertTo-Json -InputObject $Ids -Compress)
            Count        = $Ids.Count
            Done         = 0
            Copied       = 0
            Failed       = 0
            State        = 'Pending'
        } -Force
        1
    }
    $SaveCheckpoint = {
        foreach ($P in @{ PlanFolderIndex = $FolderIndex; PlanSkip = $Skip; ChunkCount = $ChunkCount; ListedItems = $Listed; AlreadyPresent = $AlreadyPresent }.GetEnumerator()) {
            $Op | Add-Member -NotePropertyName $P.Key -NotePropertyValue $P.Value -Force
        }
        $null = Add-CIPPAzDataTableEntity @Table -Entity $Op -Force
    }

    try {
        while ($FolderIndex -lt $Folders.Count) {
            $Folder = $Folders[$FolderIndex]
            # Each folder row names its own mailbox and API: archive folders live in a different mailbox
            # and are only reachable through beta. Rows from before archive support fall back to the op.
            $SrcMailboxId = [string]($Folder.SrcMailboxId ?? $Op.SrcMailboxId)
            $Base = "https://graph.microsoft.com/$([string]($Folder.SrcApi ?? 'v1.0'))/admin/exchange/mailboxes/$SrcMailboxId/folders"
            if ([int]$Folder.ItemCount -gt 0) {
                $Present = $null
                if ($Dedupe) {
                    $DstBase = "https://graph.microsoft.com/$([string]($Folder.DstApi ?? 'v1.0'))/admin/exchange/mailboxes/$([string]($Folder.DstMailboxId ?? $Op.DstMailboxId))/folders"
                    $Present = [System.Collections.Generic.HashSet[string]]::new()
                    foreach ($D in @(New-GraphGetRequest -uri "$DstBase/$($Folder.DstFolderId)/items?`$select=id&`$top=250&$KeyExpand" -tenantid $TenantFilter -AsApp $true)) {
                        $K = & $SearchKey $D
                        if ($K) { $null = $Present.Add([string]$K) }
                    }
                }
                $Select = if ($Dedupe) { "`$select=id,size&$KeyExpand" } else { '$select=id,size' }
                while ($true) {
                    $Uri = "$Base/$($Folder.SrcFolderId)/items?$Select&`$orderby=createdDateTime&`$top=$ChunkSize&`$skip=$Skip"
                    $Page = @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -AsApp $true -noPagination $true | Where-Object { $_.id })
                    foreach ($P in $Page) {
                        if ($Present) {
                            $K = & $SearchKey $P
                            if ($K -and $Present.Contains([string]$K)) { $AlreadyPresent++; continue }
                        }
                        $Buffer.Add("$($P.id)|$([int64]($P.size ?? 0))")
                        $Listed++
                        if ($Buffer.Count -ge $ChunkSize) { $ChunkCount += & $FlushChunk $Folder $SrcMailboxId }
                    }
                    if ($Page.Count -lt $ChunkSize) { break }
                    $Skip += $Page.Count
                    if ($Stopwatch.Elapsed.TotalSeconds -gt $TimeboxSeconds) {
                        $ChunkCount += & $FlushChunk $Folder $SrcMailboxId
                        & $SaveCheckpoint
                        $null = Start-CIPPOrchestrator -InputObject ([PSCustomObject]@{
                                OrchestratorName = "MailboxCopyPlanResume_$($OperationId.Substring(0, 8))_$([guid]::NewGuid().ToString('N').Substring(0, 6))"
                                Batch            = @([PSCustomObject]@{ FunctionName = 'MailboxCopyPlan'; OperationId = $OperationId; TenantFilter = $TenantFilter })
                                SkipLog          = $true
                            })
                        return @()
                    }
                }
                $ChunkCount += & $FlushChunk $Folder $SrcMailboxId
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

    $NewChunks = $ChunkCount - $FirstChunk
    $Op | Add-Member -NotePropertyName Status -NotePropertyValue $(if ($NewChunks -gt 0) { 'Copying' } else { 'Completed' }) -Force
    if ($NewChunks -le 0) { $Op | Add-Member -NotePropertyName Finished -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force }
    & $SaveCheckpoint
    if ($NewChunks -le 0) {
        Write-LogMessage -API 'MailboxCopy' -tenant $TenantFilter -message "Mailbox copy ${OperationId}: nothing left to copy ($AlreadyPresent items already in the destination)" -sev Info
        return @()
    }

    $NewRows = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$OperationId' and RowKey gt '$('c{0:D5}' -f $FirstChunk)' and RowKey lt 'd'" -Property RowKey, DstMailboxId | Sort-Object RowKey)
    $LaneNumber = 0
    foreach ($Group in @($NewRows | Group-Object { [string]($_.DstMailboxId ?? $Op.DstMailboxId) })) {
        $Keys = @($Group.Group.RowKey)
        $Count = [Math]::Min($LanesPerMailbox, $Keys.Count)
        for ($Lane = 0; $Lane -lt $Count; $Lane++) {
            $Batch = for ($c = $Lane; $c -lt $Keys.Count; $c += $Count) {
                [PSCustomObject]@{ FunctionName = 'MailboxCopyChunk'; OperationId = $OperationId; TenantFilter = $TenantFilter; ChunkKey = $Keys[$c] }
            }
            $null = Start-CIPPOrchestrator -InputObject ([PSCustomObject]@{
                    OrchestratorName = "MailboxCopy_$($OperationId.Substring(0, 8))_lane$LaneNumber"
                    Batch            = @($Batch)
                    Sequential       = $true
                    SkipLog          = $true
                })
            $LaneNumber++
        }
    }
    Write-LogMessage -API 'MailboxCopy' -tenant $TenantFilter -message "Mailbox copy ${OperationId}: queued $Listed items in $NewChunks chunks$(if ($Dedupe) { " ($AlreadyPresent already in the destination, skipped)" }); copying" -sev Info
    return @()
}
