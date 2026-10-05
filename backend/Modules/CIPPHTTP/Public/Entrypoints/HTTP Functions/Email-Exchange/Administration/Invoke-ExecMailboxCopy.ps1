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
        creates the folders and queues the copy; Cancel (with OperationId) stops a running copy after
        the chunks in flight. Track progress with ListMailboxCopies.
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
        if (-not $TenantFilter) { throw 'tenantFilter is required.' }
        if (-not $SourceUser -or -not $DestinationUser) { throw 'SourceUser and DestinationUser are required.' }
        if ($Action -notin @('Preflight', 'Start')) { throw "Unknown Action '$Action'. Use Preflight, Start or Cancel." }

        $User = try { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Headers.'x-ms-client-principal')) | ConvertFrom-Json } catch { $null }
        $StartedBy = $User.userDetails ?? $Headers.'x-ms-client-principal-name' ?? 'CIPP-API'

        $Result = Start-CIPPMailboxCopy -TenantFilter $TenantFilter -SourceUser $SourceUser -DestinationUser $DestinationUser `
            -Mode $Action -Destination $Destination -Operation $Operation -FolderName $FolderName `
            -IncludeDeletedItems $IncludeDeletedItems -IncludeJunk $IncludeJunk `
            -IncludeArchive $IncludeArchive -ArchiveDestination $ArchiveDestination -StartedBy $StartedBy -Headers $Headers -APIName $APIName
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
