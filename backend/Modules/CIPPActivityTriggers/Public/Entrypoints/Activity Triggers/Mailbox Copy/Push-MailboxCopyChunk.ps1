function Push-MailboxCopyChunk {
    <#
    .SYNOPSIS
        Exports one chunk of mailbox items and imports them into the destination folder (resumable)
    .DESCRIPTION
        One item at a time: exportItems -> import session, through [CIPP.CippMailboxTransfer]
        (backend/Shared/CIPPSharp/CippMailboxTransfer.cs). That class keeps the exported item as bytes
        and posts the import straight from the same buffer, so an item costs about one copy of its
        base64 in memory. The earlier PowerShell path (Invoke-RestMethod + ConvertFrom-Json + a JSON
        import body) held ~7x that as UTF-16 strings, and ran the B2 plan out of memory on the 3E
        archive copy even with small groups. One item per export also ends the "NotReturned" items that
        multi-item exports silently dropped.

        Throttling: Exchange answers 429 "Application is over its IncomingBytes limit" when the
        app imports too fast. 429/5xx/network errors back off (Retry-After when given, else 15s doubling,
        capped at 5 min) for up to 8 attempts before an item counts as failed.

        For Move the source item is soft-deleted (recoverable from Recoverable Items) after its import.
        Archive mailboxes: an export answered with ErrorArchiveFolderMovedPermanently is reissued at the
        URL in the error, and an import answered 409 "expected in mailbox MBX:..." gets a new import
        session for that mailbox.

        Progress (Done/Copied/Failed + last errors) is saved every few items and after every large one,
        so a requeue resumes after the last saved item. Failed items are simply absent from the
        destination; ExecMailboxCopy Action=Resume re-plans and copies only what is missing.
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param($Item)

    $OperationId = [string]$Item.OperationId
    $TenantFilter = [string]$Item.TenantFilter
    $ChunkKey = [string]$Item.ChunkKey
    $TimeboxSeconds = 900
    $MaxAttempts = 8
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $Table = Get-CippTable -tablename 'MailboxCopy'
    $Op = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Operation' and RowKey eq '$OperationId'"
    $Chunk = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$OperationId' and RowKey eq '$ChunkKey'"
    if (-not $Op -or -not $Chunk -or $Chunk.State -eq 'Done' -or $Op.Status -eq 'Cancelled') { return @() }
    # A resume re-plans into new chunks numbered after PlanFirstChunk; lanes from the earlier run that are
    # still queued must not copy their (superseded) chunks again.
    $FirstChunk = [int]($Op.PlanFirstChunk ?? 0)
    if ([int]($ChunkKey.TrimStart('c')) -le $FirstChunk) { return @() }

    # Chunks name their own mailboxes and API version: an online archive is a separate mailbox that only
    # beta will serve. Chunks written before archive support fall back to the operation's pair.
    $SrcMailboxId = [string]($Chunk.SrcMailboxId ?? $Op.SrcMailboxId)
    $DstMailboxId = [string]($Chunk.DstMailboxId ?? $Op.DstMailboxId)
    $SrcGraph = "https://graph.microsoft.com/$([string]($Chunk.SrcApi ?? 'v1.0'))/admin/exchange/mailboxes"
    $DstGraph = "https://graph.microsoft.com/$([string]($Chunk.DstApi ?? 'v1.0'))/admin/exchange/mailboxes"
    $Items = @(([string]$Chunk.Ids | ConvertFrom-Json) | ForEach-Object {
            $Parts = ([string]$_).Split('|')
            [PSCustomObject]@{ Id = $Parts[0]; Size = [int64]($Parts[1] ?? 0) }
        })
    $Done = [int]$Chunk.Done
    $Copied = [int]$Chunk.Copied
    $Failed = [int]$Chunk.Failed
    $Errors = [System.Collections.Generic.List[string]]::new()
    foreach ($E in @(try { [string]$Chunk.Errors | ConvertFrom-Json } catch { @() })) { if ($E) { $Errors.Add([string]$E) } }
    $IsMove = $Op.Operation -eq 'Move'

    $AddError = {
        param($Text)
        $Errors.Add(([string]$Text).Substring(0, [Math]::Min(300, ([string]$Text).Length)))
        while ($Errors.Count -gt 5) { $Errors.RemoveAt(0) }
    }
    $Save = {
        param($State)
        $Chunk | Add-Member -NotePropertyName Done -NotePropertyValue $Done -Force
        $Chunk | Add-Member -NotePropertyName Copied -NotePropertyValue $Copied -Force
        $Chunk | Add-Member -NotePropertyName Failed -NotePropertyValue $Failed -Force
        $Chunk | Add-Member -NotePropertyName Errors -NotePropertyValue ([string](ConvertTo-Json -InputObject @($Errors) -Compress)) -Force
        $Chunk | Add-Member -NotePropertyName State -NotePropertyValue $State -Force
        $null = Add-CIPPAzDataTableEntity @Table -Entity $Chunk -Force
    }
    # Wait before retry attempt N: the server's Retry-After when it gave one, else 15s doubling, max 5 min.
    $Backoff = {
        param([int]$Attempt, [double]$RetryAfter)
        $Seconds = if ($RetryAfter -gt 0) { [Math]::Min(300, [Math]::Ceiling($RetryAfter)) } else { [Math]::Min(300, 15 * [Math]::Pow(2, $Attempt - 1)) }
        Start-Sleep -Seconds $Seconds
    }
    $Retryable = { param([int]$Status) $Status -eq 0 -or $Status -eq 429 -or $Status -ge 500 }
    $IsOutOfMemory = { param($Err) $Err.Exception -is [System.OutOfMemoryException] -or $Err.Exception.InnerException -is [System.OutOfMemoryException] }

    # Hashtable so the scriptblocks can refresh cached state (a plain variable would not survive the child scope).
    # ImportMailbox moves when an auto-expanded archive answers 409 "expected in mailbox MBX:...".
    $Ctx = @{ Session = $null; ImportMailbox = $DstMailboxId }
    $GetSession = {
        $S = $Ctx.Session
        if (-not $S -or ([DateTime]$S.expirationDateTime).ToUniversalTime() -lt [DateTime]::UtcNow.AddMinutes(5)) {
            $S = New-GraphPOSTRequest -uri "$DstGraph/$($Ctx.ImportMailbox)/createImportSession" -tenantid $TenantFilter -body '{}' -AsApp $true
            if (-not $S.importUrl) { throw 'createImportSession returned no importUrl.' }
            $Ctx.Session = $S
        }
        $S
    }

    # Export one item, with retries and the archive redirect. Returns @{ Export; Mailbox }, @{ Skip } or @{ Error }.
    $ExportOne = {
        param($G)
        $Uri = "$SrcGraph/$SrcMailboxId/exportItems"
        $Mailbox = $SrcMailboxId
        $Redirected = $false
        $LastStatus = 0
        for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
            $X = $null
            try {
                $Auth = (Get-GraphToken -tenantid $TenantFilter -AsApp $true -SkipCache ($LastStatus -eq 401)).Authorization
                $X = Invoke-CIPPMailboxItemExport -ExportUri $Uri -Authorization ([string]$Auth) -ItemId ([string]$G.Id) -FolderId ([string]$Chunk.DstFolderId)
            } catch {
                if (& $IsOutOfMemory $_) {
                    [System.GC]::Collect()
                    return @{ Error = "Export ran out of memory (reported size $([Math]::Round($G.Size / 1MB, 1)) MB)" }
                }
                $LastStatus = 0
                if ($Attempt -lt $MaxAttempts) { & $Backoff $Attempt 0; continue }
                return @{ Error = "Export: $($_.Exception.InnerException.Message ?? $_.Exception.Message)" }
            }
            if ($X.HasData) { return @{ Export = $X; Mailbox = $Mailbox } }
            $LastStatus = [int]$X.StatusCode
            if ($LastStatus -eq 401 -and $Attempt -lt $MaxAttempts) { continue }
            if ((& $Retryable $LastStatus) -and $Attempt -lt $MaxAttempts) { & $Backoff $Attempt $X.RetryAfterSeconds; continue }
            # No data: an error entry for the item, a redirect, an HTTP error, or nothing at all.
            $Entry = $null
            try { $Entry = @(($X.Body | ConvertFrom-Json -ErrorAction Stop).value)[0] } catch { }
            $Code = [string]($Entry.error.code ?? $(if ($LastStatus -ne 200) { "HTTP $LastStatus" } else { 'NotReturned' }))
            if ($Code -eq 'ErrorArchiveFolderMovedPermanently' -and -not $Redirected -and [string]$Entry.error.message -match '^https://graph\.microsoft\.com/') {
                $Uri = [string]$Entry.error.message
                $Mailbox = if ($Uri -match '/mailboxes/([^/]+)/') { $Matches[1] } else { $SrcMailboxId }
                $Redirected = $true
                $Attempt = 0
                continue
            }
            if ($Code -match 'NotFound') { return @{ Skip = $true } }
            $Detail = [string]($Entry.error.message ?? $(if ($LastStatus -ne 200) { $X.Body } else { '' }))
            return @{ Error = "Export $($Code): $Detail (reported size $([Math]::Round($G.Size / 1MB, 1)) MB)" }
        }
        @{ Error = 'Export: gave up after retries.' }
    }

    # Import one staged item, with retries. Returns $null on success, else the error text.
    $ImportOne = {
        param($X)
        for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
            try {
                $S = & $GetSession
                $R = Invoke-CIPPMailboxItemImport -Export $X -ImportUrl ([string]$S.importUrl)
            } catch {
                if (& $IsOutOfMemory $_) {
                    [System.GC]::Collect()
                    return "Import ran out of memory ($([Math]::Round($X.DataLength / 1MB, 1)) MB exported)"
                }
                if ($Attempt -lt $MaxAttempts) { & $Backoff $Attempt 0; continue }
                return "Import: $($_.Exception.InnerException.Message ?? $_.Exception.Message)"
            }
            if ($R.Success) { return $null }
            $Status = [int]$R.StatusCode
            # Auto-expanded archive: the folder lives in an auxiliary mailbox, named in the 409.
            if ($Status -eq 409 -and [string]$R.Body -match 'expected in mailbox (MBX:[^\s."]+)' -and $Matches[1] -ne $Ctx.ImportMailbox) {
                $Ctx.ImportMailbox = $Matches[1]
                $Ctx.Session = $null
                continue
            }
            if ($Status -in @(401, 403) -and $Attempt -lt $MaxAttempts) { $Ctx.Session = $null; continue }
            if ((& $Retryable $Status) -and $Attempt -lt $MaxAttempts) { & $Backoff $Attempt $R.RetryAfterSeconds; continue }
            return "Import ($Status): $($R.Body)"
        }
        'Import: gave up after retries.'
    }

    try {
        $SinceSave = 0
        while ($Done -lt $Items.Count) {
            # A cancel takes effect within a few items, not only between chunks.
            if ($Done % 5 -eq 0) {
                $Current = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Operation' and RowKey eq '$OperationId'" -Property Status
                if ($Current.Status -eq 'Cancelled') { & $Save 'Cancelled'; return @() }
            }

            $G = $Items[$Done]
            $Big = $false
            $Got = & $ExportOne $G
            if ($Got.Export) {
                $X = $Got.Export
                $FromMailbox = $Got.Mailbox
                $Big = $X.DataLength -ge 5MB
                $ImportError = & $ImportOne $X
                $X.Release()
                $X = $null
                $Got = $null
                if ($ImportError) {
                    $Failed++
                    & $AddError $ImportError
                } else {
                    $Copied++
                    if ($IsMove) {
                        try {
                            $null = New-GraphPOSTRequest -uri "$SrcGraph/$FromMailbox/folders/$($Chunk.SrcFolderId)/items/$($G.Id)?disposalType=softDelete" -tenantid $TenantFilter -type DELETE -AsApp $true
                        } catch {
                            & $AddError "Copied but not removed from source: $(Get-NormalizedError -message $_.Exception.Message)"
                        }
                    }
                }
                if ($Big) { [System.GC]::Collect() }
            } elseif ($Got.Error) {
                $Failed++
                & $AddError $Got.Error
            }
            # Skip (gone since planning) counts as done, neither copied nor failed.
            $Done++
            $SinceSave++
            if ($Big -or $SinceSave -ge 5 -or $Done -ge $Items.Count) { & $Save 'Running'; $SinceSave = 0 }

            if ($Done -lt $Items.Count -and $Stopwatch.Elapsed.TotalSeconds -gt $TimeboxSeconds) {
                & $Save 'Running'
                $null = Start-CIPPOrchestrator -InputObject ([PSCustomObject]@{
                        OrchestratorName = "MailboxCopyResume_$($OperationId.Substring(0, 8))_${ChunkKey}_$([guid]::NewGuid().ToString('N').Substring(0, 6))"
                        Batch            = @([PSCustomObject]@{ FunctionName = 'MailboxCopyChunk'; OperationId = $OperationId; TenantFilter = $TenantFilter; ChunkKey = $ChunkKey })
                        SkipLog          = $true
                    })
                return @()
            }
        }
    } catch {
        # Unexpected failure outside the per-item handling: count the rest of the chunk as failed so
        # the operation still finishes, and keep the reason. A Resume re-plans whatever did not copy.
        $Message = Get-NormalizedError -message $_.Exception.Message
        & $AddError "Chunk stopped at item $($Done + 1): $Message"
        $Failed += ($Items.Count - $Done)
        $Done = $Items.Count
    }
    & $Save 'Done'

    # Last chunk to finish closes the operation. Only this planning pass's chunks count (a resume
    # starts numbering after PlanFirstChunk).
    $Range = "PartitionKey eq '$OperationId' and RowKey gt '$('c{0:D5}' -f $FirstChunk)' and RowKey lt 'd'"
    $Remaining = @(Get-CIPPAzDataTableEntity @Table -Filter "$Range and State ne 'Done'" -Property RowKey)
    if ($Remaining.Count -eq 0) {
        $All = @(Get-CIPPAzDataTableEntity @Table -Filter $Range)
        $TotalCopied = [int](($All | Measure-Object -Property Copied -Sum).Sum)
        $TotalFailed = [int](($All | Measure-Object -Property Failed -Sum).Sum)
        $Op = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Operation' and RowKey eq '$OperationId'"
        if ($Op.Status -eq 'Cancelled') { return @() }
        $Op | Add-Member -NotePropertyName Status -NotePropertyValue $(if ($TotalFailed -gt 0) { 'CompletedWithErrors' } else { 'Completed' }) -Force
        $Op | Add-Member -NotePropertyName Finished -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
        $null = Add-CIPPAzDataTableEntity @Table -Entity $Op -Force
        Write-LogMessage -API 'MailboxCopy' -tenant $TenantFilter -sev $(if ($TotalFailed -gt 0) { 'Warning' } else { 'Info' }) `
            -message "Mailbox $($Op.Operation.ToLower()) $OperationId finished: $($Op.SourceUser) -> $($Op.DestinationUser), $TotalCopied copied, $TotalFailed failed$(if ([int]($Op.AlreadyPresent ?? 0)) { ", $($Op.AlreadyPresent) already present from earlier runs" })"
    }
    return @()
}
