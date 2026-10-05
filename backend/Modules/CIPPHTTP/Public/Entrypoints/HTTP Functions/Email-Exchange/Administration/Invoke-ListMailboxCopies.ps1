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
        $Chunks = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$($Op.RowKey)' and RowKey ge 'c' and RowKey lt 'd'" -Property RowKey, Count, Done, Copied, Failed, State, Errors)
        $Copied = [int](($Chunks | Measure-Object -Property Copied -Sum).Sum)
        $Failed = [int](($Chunks | Measure-Object -Property Failed -Sum).Sum)
        $Planned = [int]($Op.ListedItems ?? $Op.PlannedItems ?? 0)
        if ($Op.Status -eq 'Planning') { $Planned = [int]($Op.PlannedItems ?? 0) }
        $Processed = [int](($Chunks | Measure-Object -Property Done -Sum).Sum)
        $Errors = @($Chunks | ForEach-Object { try { [string]$_.Errors | ConvertFrom-Json } catch { } } | Where-Object { $_ } | Select-Object -Last 5)
        [PSCustomObject]@{
            OperationId       = $Op.RowKey
            Tenant            = $Op.TenantFilter
            Operation         = $Op.Operation
            SourceUser        = $Op.SourceUser
            DestinationUser   = $Op.DestinationUser
            DestinationFolder = $(if ($Op.DestinationFolder) { $Op.DestinationFolder } else { '(merged into existing folders)' })
            Status            = $Op.Status
            ProgressPercent   = $(if ($Planned -gt 0) { [Math]::Min(100, [Math]::Round(100 * $Processed / $Planned)) } else { 0 })
            ItemsTotal        = $Planned
            ItemsCopied       = $Copied
            ItemsFailed       = $Failed
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
