function Invoke-ExecMailboxCopy {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Exchange.Mailbox.ReadWrite
    .DESCRIPTION
        Copies or moves one mailbox's content (mail, calendar, contacts, tasks) into another mailbox
        through the Graph full-fidelity export/import API: into a new folder ("From <name> (<date>)"
        unless FolderName is given) or merged into the destination's own folders (Destination=Root).
        Operation=Move deletes each source item after it is imported. IncludeDeletedItems and
        IncludeJunk are off by default. IncludeArchive (on by default) also copies the source's online
        archive: into the destination's archive (ArchiveDestination=Archive, the default) or into an
        "Online Archive" folder in their main mailbox (ArchiveDestination=Primary, also the fallback
        when the destination has no archive). Action Preflight counts without changing anything; Start
        creates the folders and queues the copy; Cancel (with OperationId) stops a running copy between
        item groups. Resume (with OperationId) restarts a cancelled, failed or partly failed copy and
        copies only what is missing: the planner compares PR_SEARCH_KEY against the destination folders,
        so items copied by an earlier run are skipped rather than duplicated. Track progress with
        ListMailboxCopies.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Body.tenantFilter.value ?? $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $Action = [string]($Request.Body.Action ?? $Request.Query.Action ?? 'Preflight')
    $SourceUser = $Request.Body.SourceUser.value ?? $Request.Body.SourceUser ?? $Request.Body.userPrincipalName
    $DestinationUser = $Request.Body.DestinationUser.value ?? $Request.Body.DestinationUser
    $FolderName = [string]$Request.Body.FolderName
    # Form autocompletes post {label, value}; plain strings work too.
    $Destination = [string]($Request.Body.Destination.value ?? $Request.Body.Destination ?? 'NewFolder')
    $Operation = [string]($Request.Body.Operation.value ?? $Request.Body.Operation ?? 'Copy')
    $IncludeDeletedItems = ConvertTo-CIPPBoolean -Value ($Request.Body.IncludeDeletedItems ?? $false)
    $IncludeJunk = ConvertTo-CIPPBoolean -Value ($Request.Body.IncludeJunk ?? $false)
    $IncludeArchive = ConvertTo-CIPPBoolean -Value ($Request.Body.IncludeArchive ?? $true)
    $ArchiveDestination = [string]($Request.Body.ArchiveDestination.value ?? $Request.Body.ArchiveDestination ?? 'Archive')
    # Test hook: a small worker time budget forces lane hand-offs on a small copy. Not in the UI.
    $SoftSeconds = [int]($Request.Body.SoftSeconds ?? 0)

    try {
        if ($Action -eq 'Cancel') {
            $OperationId = [string]($Request.Body.OperationId ?? $Request.Query.OperationId)
            if ($OperationId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'OperationId is required to cancel.' }
            $Table = Get-CippTable -tablename 'MailboxCopy'
            $Op = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Operation' and RowKey eq '$OperationId'"
            if (-not $Op) { throw "Mailbox copy $OperationId was not found." }
            $Op | Add-Member -NotePropertyName Status -NotePropertyValue 'Cancelled' -Force
            Add-CIPPAzDataTableEntity @Table -Entity $Op -Force
            Write-LogMessage -headers $Headers -API $APIName -tenant $Op.TenantFilter -message "Cancelled mailbox copy $OperationId ($($Op.SourceUser) -> $($Op.DestinationUser))" -sev Info
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = "Cancelled. Chunks already running finish their current items; nothing new starts." } })
        }
        if ($Action -eq 'Resume') {
            $OperationId = [string]($Request.Body.OperationId ?? $Request.Query.OperationId)
            if ($OperationId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'OperationId is required to resume.' }
            $Table = Get-CippTable -tablename 'MailboxCopy'
            $Op = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Operation' and RowKey eq '$OperationId'"
            if (-not $Op) { throw "Mailbox copy $OperationId was not found." }
            # Chunks of an earlier run finish their current item before stopping. Resuming under them would
            # race them into the same folders, so wait until every chunk of the current pass has gone quiet.
            # A copy still marked Planning/Copying can be resumed only when nothing has moved for 10 minutes
            # (its workers were lost, e.g. to an app restart); otherwise it has to be cancelled first.
            $FirstChunk = [int]($Op.PlanFirstChunk ?? 0)
            $Chunks = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$OperationId' and RowKey gt '$('c{0:D5}' -f $FirstChunk)' and RowKey lt 'd'" -Property RowKey, State, Timestamp)
            $Stamps = @(@($Op) + $Chunks | Where-Object { $_.Timestamp } | ForEach-Object { ([DateTimeOffset]$_.Timestamp).UtcDateTime })
            $LastActivity = ($Stamps | Measure-Object -Maximum).Maximum
            if ($Op.Status -in @('Planning', 'Copying')) {
                if ($LastActivity -and $LastActivity -gt [DateTime]::UtcNow.AddMinutes(-10)) {
                    throw "This copy is still $($Op.Status.ToLower()) (last progress $([int]([DateTime]::UtcNow - $LastActivity).TotalMinutes) min ago). Cancel it first, or let it finish."
                }
            }
            # 6 minutes: a chunk writes a heartbeat before each throttle sleep, and sleeps at most 300s.
            $Busy = @($Chunks | Where-Object { $_.State -eq 'Running' -and $_.Timestamp -and ([DateTimeOffset]$_.Timestamp).UtcDateTime -gt [DateTime]::UtcNow.AddMinutes(-6) })
            if ($Busy.Count -gt 0) { throw "$($Busy.Count) chunk(s) of the earlier run are still finishing their current items. Try again in a few minutes." }

            foreach ($P in @{
                    Status = 'Planning'; Dedupe = $true; PlanFirstChunk = [int]($Op.ChunkCount ?? 0); PlanFolderIndex = 0; PlanSkip = 0
                    ListedItems = 0; AlreadyPresent = 0; ResumeCount = [int]($Op.ResumeCount ?? 0) + 1; Message = ''; Finished = ''
                }.GetEnumerator()) {
                $Op | Add-Member -NotePropertyName $P.Key -NotePropertyValue $P.Value -Force
            }
            Add-CIPPAzDataTableEntity @Table -Entity $Op -Force
            $null = Start-CIPPOrchestrator -InputObject ([PSCustomObject]@{
                    OrchestratorName = "MailboxCopyPlan_$($OperationId.Substring(0, 8))_resume$($Op.ResumeCount)"
                    Batch            = @([PSCustomObject]@{ FunctionName = 'MailboxCopyPlan'; OperationId = $OperationId; TenantFilter = $Op.TenantFilter })
                    SkipLog          = $true
                })
            Write-LogMessage -headers $Headers -API $APIName -tenant $Op.TenantFilter -message "Resumed mailbox copy $OperationId ($($Op.SourceUser) -> $($Op.DestinationUser)); copying only items not already in the destination" -sev Info
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = 'Resumed. CIPP is comparing the destination with the source and will copy only the items that are missing. Progress: Mailbox Copies.' } })
        }
        if (-not $TenantFilter) { throw 'tenantFilter is required.' }
        if (-not $SourceUser -or -not $DestinationUser) { throw 'SourceUser and DestinationUser are required.' }
        if ($Action -notin @('Preflight', 'Start')) { throw "Unknown Action '$Action'. Use Preflight, Start, Cancel or Resume." }

        $User = try { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Headers.'x-ms-client-principal')) | ConvertFrom-Json } catch { $null }
        $StartedBy = $User.userDetails ?? $Headers.'x-ms-client-principal-name' ?? 'CIPP-API'

        $Result = Start-CIPPMailboxCopy -TenantFilter $TenantFilter -SourceUser $SourceUser -DestinationUser $DestinationUser `
            -Mode $Action -Destination $Destination -Operation $Operation -FolderName $FolderName `
            -IncludeDeletedItems $IncludeDeletedItems -IncludeJunk $IncludeJunk `
            -IncludeArchive $IncludeArchive -ArchiveDestination $ArchiveDestination -SoftSeconds $SoftSeconds -StartedBy $StartedBy -Headers $Headers -APIName $APIName
        $StatusCode = [HttpStatusCode]::OK
        $Body = @{ Results = $Result }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Mailbox copy $Action failed: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::BadRequest
        $Body = @{ Results = "Mailbox copy failed: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
