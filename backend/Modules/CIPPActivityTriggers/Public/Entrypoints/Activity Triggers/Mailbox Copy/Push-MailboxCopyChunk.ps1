function Push-MailboxCopyChunk {
    <#
    .SYNOPSIS
        Copies a lane of mailbox-copy chunks, one item at a time, handing off to a single successor before Craft's task limit
    .DESCRIPTION
        A lane is the ordered list of chunk keys one worker owns (Item.LaneChunks; a bare Item.ChunkKey is a
        lane of one). The worker copies chunk after chunk; when its time budget runs out it saves progress
        and starts exactly one successor run for the same lane at the same position, then returns. So a lane
        is a chain of tasks with one link alive at a time, and concurrency stays at the planner's lanes per
        mailbox. (Before, a timed-out chunk spawned a separate run while its lane carried on with the next
        chunk: on the 3E copy seven of them ran at once against one mailbox, past Exchange's 4-request
        MailboxConcurrency limit.)

        Time budget: Craft kills a background task at Worker:BgTimeoutSeconds (1200s) without letting it
        record anything. A chunk that was killed mid-item stayed 'Running' for ever, and the copy sat at
        "Copying" with nothing left to run (3E, 2026-10-06). Now no item starts after 900s, no throttle
        sleep may end within 45s of the 1080s hard limit, and each HTTP call is abandoned (catchably) at the
        time left. The worker always gets to save and hand off.

        Per item: exportItems -> import session through [CIPP.CippMailboxTransfer]
        (backend/Shared/CIPPSharp/CippMailboxTransfer.cs), which keeps the item as bytes - about one copy of
        its base64 in memory. 429/5xx/network errors wait (Retry-After when given, else 15-60s) for up to 12
        attempts. Exchange caps imports at ~150 MB per 5 minutes per destination mailbox; that cap, not CIPP,
        sets the pace of a big copy. For Move the source item is soft-deleted after its import. Archive
        redirects (ErrorArchiveFolderMovedPermanently on export, 409 "expected in mailbox" on import) are
        followed.

        Progress is saved every few items, after every large one and before every wait. Failed items are
        simply absent from the destination; ExecMailboxCopy Action=Resume re-plans and copies only what is
        missing.
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param($Item)

    $OperationId = [string]$Item.OperationId
    $TenantFilter = [string]$Item.TenantFilter
    # Always an array: a one-element pipeline result is a bare string, and indexing that returns characters.
    $LaneChunks = @(@(if ($Item.LaneChunks) { $Item.LaneChunks } else { $Item.ChunkKey }) | ForEach-Object { [string]$_ })
    $Position = [int]($Item.LanePosition ?? 0)
    $Hop = [int]($Item.Hop ?? 0)
    $Lane = [string]($Item.Lane ?? "MailboxCopy_$($OperationId.Substring(0, [Math]::Min(8, $OperationId.Length)))_$($LaneChunks[0])")
    # Craft kills background tasks at 1200s. Start no item after $SoftSeconds; end every wait and call
    # before $HardSeconds. ($Item.SoftSeconds/HardSeconds exist for tests.)
    $SoftSeconds = [int]($Item.SoftSeconds ?? 900)
    $HardSeconds = [int]($Item.HardSeconds ?? 1080)
    $MaxAttempts = 12
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $SecondsLeft = { $HardSeconds - $Stopwatch.Elapsed.TotalSeconds }
    # Per-call timeout: what is left of the budget, never less than 15s.
    $CallBudget = { [int][Math]::Max(15, [Math]::Floor((& $SecondsLeft) - 15)) }
    $StopSignal = 'CIPP-MAILBOXCOPY-STOP'
    $TimeboxSignal = 'CIPP-MAILBOXCOPY-TIMEBOX'

    $Successor = {
        param([int]$At)
        $Next = [PSCustomObject]@{
            FunctionName = 'MailboxCopyChunk'
            OperationId  = $OperationId
            TenantFilter = $TenantFilter
            Lane         = $Lane
            LaneChunks   = @($LaneChunks)
            LanePosition = $At
            Hop          = $Hop + 1
        }
        foreach ($P in 'SoftSeconds', 'HardSeconds') { if ($Item.$P) { $Next | Add-Member -NotePropertyName $P -NotePropertyValue $Item.$P } }
        $null = Start-CIPPOrchestrator -InputObject ([PSCustomObject]@{
                OrchestratorName = "$($Lane)_h$($Hop + 1)"
                Batch            = @($Next)
                SkipLog          = $true
            })
    }

    # Copies one chunk. Returns 'Done', 'Timebox' (budget spent; progress saved) or 'Stopped' (cancelled/superseded).
    function Invoke-MailboxCopyOneChunk {
        param([string]$ChunkKey)
        $Table = Get-CippTable -tablename 'MailboxCopy'
        $Op = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Operation' and RowKey eq '$OperationId'"
        $Chunk = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$OperationId' and RowKey eq '$ChunkKey'"
        if (-not $Op -or $Op.Status -eq 'Cancelled') { return 'Stopped' }
        if (-not $Chunk) { throw "Chunk $ChunkKey of mailbox copy $OperationId could not be read." }
        if ($Chunk.State -eq 'Done') { return 'Done' }
        # A resume re-plans into new chunks numbered after PlanFirstChunk; lanes from the earlier run that are
        # still queued must not copy their (superseded) chunks again.
        $FirstChunk = [int]($Op.PlanFirstChunk ?? 0)
        $ChunkNumber = [int]($ChunkKey.TrimStart('c'))
        if ($ChunkNumber -le $FirstChunk) { return 'Stopped' }

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
        # Wait before retry attempt N: the server's Retry-After when it gave one, else 15s, 30s, 45s, then
        # 60s. Exchange's import budget is a rolling 5-minute window, so short regular waits use it as it
        # frees up; doubling to minutes left it idle (measured on the 3E copy).
        $Backoff = {
            param([int]$Attempt, [double]$RetryAfter, [int]$Status, [string]$Stage)
            $Seconds = if ($RetryAfter -gt 0) { [Math]::Min(300, [Math]::Ceiling($RetryAfter)) } else { [Math]::Min(60, 15 * $Attempt) }
            Write-Information "MailboxCopy $OperationId ${ChunkKey}: $Stage HTTP $Status, attempt $Attempt; waiting ${Seconds}s$(if ($RetryAfter -gt 0) { ' (Retry-After)' })"
            # Heartbeat first: Resume treats a chunk updated in the last 6 minutes as still working, which
            # covers the longest sleep (300s), so it can never re-plan underneath a sleeping chunk.
            & $Save 'Running'
            # Never sleep into Craft's kill: hand the rest of the lane to a successor instead.
            if ((& $SecondsLeft) - $Seconds -lt 45) { throw $TimeboxSignal }
            Start-Sleep -Seconds $Seconds
            if (-not (& $StillMine)) { throw $StopSignal }
        }
        $Retryable = { param([int]$Status) $Status -eq 0 -or $Status -eq 429 -or $Status -ge 500 }
        # False once the copy is cancelled or a Resume has re-planned past this chunk. A chunk can sleep for
        # minutes in throttle back-off, so this is checked after every sleep as well as every few items.
        $StillMine = {
            $Current = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Operation' and RowKey eq '$OperationId'" -Property Status, PlanFirstChunk
            $Current.Status -ne 'Cancelled' -and [int]($Current.PlanFirstChunk ?? 0) -lt $ChunkNumber
        }
        $StopSignal = 'CIPP-MAILBOXCOPY-STOP'
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
                    $X = Invoke-CIPPMailboxItemExport -ExportUri $Uri -Authorization ([string]$Auth) -ItemId ([string]$G.Id) -FolderId ([string]$Chunk.DstFolderId) -TimeoutSeconds (& $CallBudget)
                } catch {
                    if (& $IsOutOfMemory $_) {
                        [System.GC]::Collect()
                        return @{ Error = "Export ran out of memory (reported size $([Math]::Round($G.Size / 1MB, 1)) MB)" }
                    }
                    $LastStatus = 0
                    if ($Attempt -lt $MaxAttempts) { & $Backoff $Attempt 0 0 'export'; continue }
                    return @{ Error = "Export: $($_.Exception.InnerException.Message ?? $_.Exception.Message)" }
                }
                if ($X.HasData) { return @{ Export = $X; Mailbox = $Mailbox } }
                $LastStatus = [int]$X.StatusCode
                if ($LastStatus -eq 401 -and $Attempt -lt $MaxAttempts) { continue }
                if ((& $Retryable $LastStatus) -and $Attempt -lt $MaxAttempts) { & $Backoff $Attempt $X.RetryAfterSeconds $LastStatus 'export'; continue }
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
                    $R = Invoke-CIPPMailboxItemImport -Export $X -ImportUrl ([string]$S.importUrl) -TimeoutSeconds (& $CallBudget)
                } catch {
                    if (& $IsOutOfMemory $_) {
                        [System.GC]::Collect()
                        return "Import ran out of memory ($([Math]::Round($X.DataLength / 1MB, 1)) MB exported)"
                    }
                    if ($Attempt -lt $MaxAttempts) { & $Backoff $Attempt 0 0 'import'; continue }
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
                if ((& $Retryable $Status) -and $Attempt -lt $MaxAttempts) { & $Backoff $Attempt $R.RetryAfterSeconds $Status 'import'; continue }
                return "Import ($Status): $($R.Body)"
            }
            'Import: gave up after retries.'
        }

        try {
            $SinceSave = 0
            while ($Done -lt $Items.Count) {
                # A cancel takes effect within a few items, not only between chunks.
                if ($Done % 5 -eq 0 -and -not (& $StillMine)) { & $Save 'Stopped'; return 'Stopped' }
                # Out of time for another item: save and let a successor continue from here.
                if ($Stopwatch.Elapsed.TotalSeconds -gt $SoftSeconds) { & $Save 'Running'; return 'Timebox' }

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

            }
        } catch {
            if ([string]$_.Exception.Message -eq $StopSignal -or [string]$_ -eq $StopSignal) {
                # Cancelled or superseded while waiting out a throttle: the item in hand was not imported.
                & $Save 'Stopped'
                return 'Stopped'
            }
            if ([string]$_.Exception.Message -eq $TimeboxSignal -or [string]$_ -eq $TimeboxSignal) {
                # A throttle wait would have run past the time budget: the item in hand was not imported,
                # so the successor starts from it again.
                & $Save 'Running'
                return 'Timebox'
            }
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
            if ($Op.Status -eq 'Cancelled') { return 'Done' }
            $Op | Add-Member -NotePropertyName Status -NotePropertyValue $(if ($TotalFailed -gt 0) { 'CompletedWithErrors' } else { 'Completed' }) -Force
            $Op | Add-Member -NotePropertyName Finished -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
            $null = Add-CIPPAzDataTableEntity @Table -Entity $Op -Force
            Write-LogMessage -API 'MailboxCopy' -tenant $TenantFilter -sev $(if ($TotalFailed -gt 0) { 'Warning' } else { 'Info' }) `
                -message "Mailbox $($Op.Operation.ToLower()) $OperationId finished: $($Op.SourceUser) -> $($Op.DestinationUser), $TotalCopied copied, $TotalFailed failed$(if ([int]($Op.AlreadyPresent ?? 0)) { ", $($Op.AlreadyPresent) already present from earlier runs" })"
        }
        return 'Done'
    }

    while ($Position -lt $LaneChunks.Count) {
        $Result = @(Invoke-MailboxCopyOneChunk -ChunkKey $LaneChunks[$Position])[-1]
        if ($Result -eq 'Stopped') { return @() }
        if ($Result -eq 'Timebox') { & $Successor $Position; return @() }
        $Position++
        if ($Position -lt $LaneChunks.Count -and $Stopwatch.Elapsed.TotalSeconds -gt $SoftSeconds) { & $Successor $Position; return @() }
    }
    return @()
}
