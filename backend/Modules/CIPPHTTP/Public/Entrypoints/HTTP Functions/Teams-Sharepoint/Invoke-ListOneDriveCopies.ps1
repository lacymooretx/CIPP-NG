function Invoke-ListOneDriveCopies {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Sharepoint.Site.Read
    .DESCRIPTION
        Lists OneDrive copies for a tenant (newest first) and refreshes the progress of any still
        running by polling their SharePoint copy jobs.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    try {
        if (-not $TenantFilter) { throw 'tenantFilter is required.' }
        $Table = Get-CIPPTable -TableName 'SharePointLibraryCopy'
        $SafeTenant = $TenantFilter -replace "'", "''"
        # Operation rows only: handle chunks are stored as '<OperationId>_<n>'.
        $Rows = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$SafeTenant' and Kind eq 'OneDriveCopy'" |
                Where-Object { $_.RowKey -notmatch '_\d+$' })

        $Results = foreach ($Row in ($Rows | Sort-Object Timestamp -Descending)) {
            $Snapshot = $null
            if ($Row.Status -notin @('Completed', 'CompletedWithErrors', 'Failed')) {
                try { $Snapshot = Update-CIPPSharePointLibraryCopyStatus -TenantFilter $TenantFilter -OperationId $Row.RowKey } catch {
                    Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Could not refresh OneDrive copy $($Row.RowKey): $($_.Exception.Message)" -sev Warning
                }
            }
            if (-not $Snapshot -and $Row.SanitizedSnapshot) { $Snapshot = $Row.SanitizedSnapshot | ConvertFrom-Json -ErrorAction SilentlyContinue }
            [PSCustomObject]@{
                OperationId       = $Row.RowKey
                Operation         = $Row.Operation ?? 'Copy'
                SourceUser        = $Row.SourceUser
                DestinationUser   = $Row.DestinationUser
                DestinationFolder = $Row.DestinationFolder
                DestinationUrl    = $Row.DestinationUrl
                StartedBy         = $Row.StartedBy
                Started           = $Row.Timestamp
                Status            = $Snapshot.Status ?? $Row.Status
                ProgressPercent   = $Snapshot.ProgressPercent
                FilesCreated      = $Snapshot.FilesCreated
                JobsComplete      = $Snapshot.JobsComplete
                JobsTotal         = $Snapshot.JobsTotal ?? $Row.JobHandleCount
                Errors            = $Snapshot.TotalErrors
                Warnings          = $Snapshot.TotalWarnings
                Message           = $Snapshot.Message
                ErrorDetails      = (@($Snapshot.Errors | ForEach-Object { $_.Message } | Select-Object -First 5) -join ' | ')
            }
        }
        $StatusCode = [HttpStatusCode]::OK
        $Body = @($Results)
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $StatusCode = [HttpStatusCode]::BadRequest
        $Body = @{ Results = "Failed to list OneDrive copies: $($ErrorMessage.NormalizedError)" }
    }
    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
