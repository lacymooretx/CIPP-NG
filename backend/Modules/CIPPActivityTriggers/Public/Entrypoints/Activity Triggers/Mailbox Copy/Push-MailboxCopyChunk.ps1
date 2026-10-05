function Push-MailboxCopyChunk {
    <#
    .SYNOPSIS
        Exports one chunk of mailbox items and imports them into the destination folder (resumable)
    .DESCRIPTION
        Groups the chunk's items into exportItems calls (max 10 items, ~10 MB), posts each item to a
        destination import session, and for Move soft-deletes the source item (recoverable from Recoverable Items) once its import succeeded.
        Archive mailboxes: follows the documented auto-expanding archive redirects - an export answered
        with ErrorArchiveFolderMovedPermanently is reissued at the URL in the error, and an import
        answered 409 "expected in mailbox MBX:..." gets a new import session for that mailbox.

        Progress (Done/Copied/Failed + last errors) is saved after every group, so a requeue or a
        retried task resumes after the last saved item instead of importing it twice.
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param($Item)

    $OperationId = [string]$Item.OperationId
    $TenantFilter = [string]$Item.TenantFilter
    $ChunkKey = [string]$Item.ChunkKey
    $TimeboxSeconds = 900
    # The export stream runs far larger than an item's reported size (a 95 KB message exported as
    # 3.8 MB of base64 in testing), so groups stay well under the API's 20-item limit.
    $MaxGroupItems = 10
    $MaxGroupBytes = 10MB
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    $Table = Get-CippTable -tablename 'MailboxCopy'
    $Op = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Operation' and RowKey eq '$OperationId'"
    $Chunk = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$OperationId' and RowKey eq '$ChunkKey'"
    if (-not $Op -or -not $Chunk -or $Chunk.State -eq 'Done' -or $Op.Status -eq 'Cancelled') { return @() }

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
        Add-CIPPAzDataTableEntity @Table -Entity $Chunk -Force
    }

    # Hashtable so the scriptblock can refresh the cached session (a plain variable would not survive the child scope).
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

    try {
        while ($Done -lt $Items.Count) {
            # Group: up to 10 items and ~10 MB (a single larger item goes on its own).
            $Group = [System.Collections.Generic.List[object]]::new()
            $Bytes = 0
            for ($i = $Done; $i -lt $Items.Count -and $Group.Count -lt $MaxGroupItems; $i++) {
                if ($Group.Count -gt 0 -and ($Bytes + $Items[$i].Size) -gt $MaxGroupBytes) { break }
                $Group.Add($Items[$i]); $Bytes += $Items[$i].Size
            }

            $Body = @{ itemIds = @($Group.Id) } | ConvertTo-Json -Compress
            $Response = New-GraphPOSTRequest -uri "$SrcGraph/$SrcMailboxId/exportItems" -tenantid $TenantFilter -body $Body -AsApp $true
            $Exported = @($Response.value ?? $Response)
            $ById = @{}
            # Which mailbox each item really lives in - an auto-expanded archive keeps some folders' items
            # in an auxiliary mailbox; Move has to delete them there.
            $ItemMailbox = @{}
            $Redirects = @{}
            foreach ($X in $Exported) {
                if (-not $X.itemId) { continue }
                $ById[[string]$X.itemId] = $X
                if ([string]$X.error.code -eq 'ErrorArchiveFolderMovedPermanently' -and [string]$X.error.message -match '^https://graph\.microsoft\.com/') {
                    $Url = [string]$X.error.message
                    if (-not $Redirects.ContainsKey($Url)) { $Redirects[$Url] = [System.Collections.Generic.List[string]]::new() }
                    $Redirects[$Url].Add([string]$X.itemId)
                }
            }
            # Reissue the export for redirected items at the URL the API named.
            foreach ($Url in $Redirects.Keys) {
                $Again = New-GraphPOSTRequest -uri $Url -tenantid $TenantFilter -body (@{ itemIds = @($Redirects[$Url]) } | ConvertTo-Json -Compress) -AsApp $true
                $AuxMailbox = if ($Url -match '/mailboxes/([^/]+)/') { $Matches[1] } else { $SrcMailboxId }
                foreach ($X in @($Again.value ?? $Again)) {
                    if ($X.itemId) { $ById[[string]$X.itemId] = $X; $ItemMailbox[[string]$X.itemId] = $AuxMailbox }
                }
            }

            foreach ($G in $Group) {
                $X = $ById[$G.Id]
                if (-not $X -or -not $X.data) {
                    # Gone since planning (deleted/moved by the user) is not a failure worth alarming on.
                    $Code = [string]($X.error.code ?? 'NotReturned')
                    if ($Code -notmatch 'NotFound') { $Failed++; & $AddError "Export $($Code): $($X.error.message)" }
                    continue
                }
                $ImportBody = @{ FolderId = [string]$Chunk.DstFolderId; Mode = 'create'; Data = [string]$X.data } | ConvertTo-Json -Compress
                $Imported = $null
                for ($Attempt = 1; $Attempt -le 4 -and -not $Imported; $Attempt++) {
                    try {
                        $S = & $GetSession
                        $Imported = Invoke-RestMethod -Method POST -Uri $S.importUrl -Body $ImportBody -ContentType 'application/json' -ErrorAction Stop
                    } catch {
                        $Status = [int]($_.Exception.Response.StatusCode ?? 0)
                        if ($Status -in @(401, 403)) { $Ctx.Session = $null }
                        # Auto-expanded archive: the folder lives in an auxiliary mailbox, named in the 409.
                        if ($Status -eq 409 -and [string]$_.ErrorDetails.Message -match 'expected in mailbox (MBX:[^\s."]+)' -and $Matches[1] -ne $Ctx.ImportMailbox) {
                            $Ctx.ImportMailbox = $Matches[1]
                            $Ctx.Session = $null
                            continue
                        }
                        if ($Attempt -lt 4 -and $Status -in @(0, 401, 403, 429, 500, 502, 503, 504)) {
                            Start-Sleep -Seconds ([Math]::Min(60, 5 * $Attempt * $Attempt))
                            continue
                        }
                        $Failed++
                        & $AddError "Import ($Status): $($_.ErrorDetails.Message ?? $_.Exception.Message)"
                        break
                    }
                }
                if (-not $Imported) { continue }
                $Copied++
                if ($IsMove) {
                    try {
                        $FromMailbox = $ItemMailbox[$G.Id] ?? $SrcMailboxId
                        $null = New-GraphPOSTRequest -uri "$SrcGraph/$FromMailbox/folders/$($Chunk.SrcFolderId)/items/$($G.Id)?disposalType=softDelete" -tenantid $TenantFilter -type DELETE -AsApp $true
                    } catch {
                        & $AddError "Copied but not removed from source: $(Get-NormalizedError -message $_.Exception.Message)"
                    }
                }
            }
            $Done += $Group.Count
            & $Save 'Running'

            if ($Done -lt $Items.Count -and $Stopwatch.Elapsed.TotalSeconds -gt $TimeboxSeconds) {
                $null = Start-CIPPOrchestrator -InputObject ([PSCustomObject]@{
                        OrchestratorName = "MailboxCopyResume_$($OperationId.Substring(0, 8))_$ChunkKey"
                        Batch            = @([PSCustomObject]@{ FunctionName = 'MailboxCopyChunk'; OperationId = $OperationId; TenantFilter = $TenantFilter; ChunkKey = $ChunkKey })
                        SkipLog          = $true
                    })
                return @()
            }
        }
    } catch {
        # Whole-group failure (export call itself failed): count the rest of the chunk as failed so
        # the operation still finishes, and keep the reason.
        $Message = Get-NormalizedError -message $_.Exception.Message
        & $AddError "Chunk stopped at item $($Done + 1): $Message"
        $Failed += ($Items.Count - $Done)
        $Done = $Items.Count
    }
    & $Save 'Done'

    # Last chunk to finish closes the operation.
    $Remaining = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$OperationId' and RowKey ge 'c' and RowKey lt 'd' and State ne 'Done'" -Property RowKey)
    if ($Remaining.Count -eq 0) {
        $All = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$OperationId' and RowKey ge 'c' and RowKey lt 'd'")
        $TotalCopied = [int](($All | Measure-Object -Property Copied -Sum).Sum)
        $TotalFailed = [int](($All | Measure-Object -Property Failed -Sum).Sum)
        $Op | Add-Member -NotePropertyName Status -NotePropertyValue $(if ($TotalFailed -gt 0) { 'CompletedWithErrors' } else { 'Completed' }) -Force
        $Op | Add-Member -NotePropertyName Finished -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
        Add-CIPPAzDataTableEntity @Table -Entity $Op -Force
        Write-LogMessage -API 'MailboxCopy' -tenant $TenantFilter -sev $(if ($TotalFailed -gt 0) { 'Warning' } else { 'Info' }) `
            -message "Mailbox $($Op.Operation.ToLower()) $OperationId finished: $($Op.SourceUser) -> $($Op.DestinationUser), $TotalCopied copied, $TotalFailed failed"
    }
    return @()
}
