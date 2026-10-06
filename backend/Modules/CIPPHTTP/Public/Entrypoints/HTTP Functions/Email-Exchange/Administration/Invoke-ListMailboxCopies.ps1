function Invoke-ListMailboxCopies {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Exchange.Mailbox.Read
    .DESCRIPTION
        Lists mailbox copy/move operations started with ExecMailboxCopy for a tenant (or all tenants with
        tenantFilter=AllTenants), with live progress summed from the operation's chunks.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    $Table = Get-CippTable -tablename 'MailboxCopy'
    $Filter = "PartitionKey eq 'Operation'"
    if ($TenantFilter -and $TenantFilter -ne 'AllTenants') {
        $Filter += " and TenantFilter eq '$(ConvertTo-CIPPODataFilterValue -Value $TenantFilter -Type String)'"
    }

    $Results = foreach ($Op in @(Get-CIPPAzDataTableEntity @Table -Filter $Filter)) {
        # After a Resume only the latest planning pass counts: its chunks are numbered after
        # PlanFirstChunk, and everything earlier runs copied is in AlreadyPresent.
        $FirstChunk = [int]($Op.PlanFirstChunk ?? 0)
        $Chunks = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$($Op.RowKey)' and RowKey gt '$('c{0:D5}' -f $FirstChunk)' and RowKey lt 'd'" -Property RowKey, Count, Done, Copied, Failed, State, Errors, Timestamp)
        $AlreadyPresent = [int]($Op.AlreadyPresent ?? 0)
        $Copied = $AlreadyPresent + [int](($Chunks | Measure-Object -Property Copied -Sum).Sum)
        $Failed = [int](($Chunks | Measure-Object -Property Failed -Sum).Sum)
        $Planned = $AlreadyPresent + [int]($Op.ListedItems ?? 0)
        if ($Op.Status -eq 'Planning') { $Planned = [int]($Op.PlannedItems ?? 0) }
        $Processed = $AlreadyPresent + [int](($Chunks | Measure-Object -Property Done -Sum).Sum)
        # A copy marked Copying/Planning with no chunk or operation update for 30 minutes has no live
        # worker (chunks write a heartbeat at least every few minutes, even while throttled). Say so,
        # so it is not mistaken for a slow copy; Resume picks it up.
        $Status = [string]$Op.Status
        if ($Status -in @('Copying', 'Planning')) {
            $Stamps = @(@($Op) + $Chunks | Where-Object { $_.Timestamp } | ForEach-Object { ([DateTimeOffset]$_.Timestamp).UtcDateTime })
            $Last = ($Stamps | Measure-Object -Maximum).Maximum
            if ($Last -and $Last -lt [DateTime]::UtcNow.AddMinutes(-30)) { $Status = 'Stalled' }
        }
        $Errors = @($Chunks | ForEach-Object { try { [string]$_.Errors | ConvertFrom-Json } catch { } } | Where-Object { $_ } | Select-Object -Last 5)
        [PSCustomObject]@{
            OperationId       = $Op.RowKey
            Tenant            = $Op.TenantFilter
            Operation         = $Op.Operation
            SourceUser        = $Op.SourceUser
            DestinationUser   = $Op.DestinationUser
            DestinationFolder = $(if ($Op.DestinationFolder) { $Op.DestinationFolder } else { '(merged into existing folders)' })
            Status            = $Status
            ProgressPercent   = $(if ($Planned -gt 0) { [Math]::Min(100, [Math]::Round(100 * $Processed / $Planned)) } else { 0 })
            ItemsTotal        = $Planned
            ItemsCopied       = $Copied
            ItemsFailed       = $Failed
            ArchiveItems      = [int]($Op.ArchiveItems ?? 0)
            ArchiveDestination = [string]($Op.ArchiveDestination ?? '')
            AlreadyPresent    = $AlreadyPresent
            Resumes           = [int]($Op.ResumeCount ?? 0)
            Folders           = [int]($Op.FolderCount ?? 0)
            ChunksDone        = @($Chunks | Where-Object { $_.State -eq 'Done' }).Count
            ChunksTotal       = $Chunks.Count
            Message           = [string]($Op.Message ?? '')
            RecentErrors      = ($Errors -join ' | ')
            StartedBy         = $Op.StartedBy
            Started           = $Op.Started
            Finished          = $Op.Finished
        }
    }

    return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = @($Results | Sort-Object Started -Descending)
        })
}
