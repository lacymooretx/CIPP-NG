function Invoke-RemoveTeamsPolicyTemplate {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Teams.Config.ReadWrite
    .DESCRIPTION
        Deletes a saved Teams policy template. Removes the template only - tenants it was
        already deployed to keep their settings.

        Body/query: ID (required) - the template GUID.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $ID = $Request.Body.ID ?? $Request.Query.ID

    if (-not $ID) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'ID is required.' }
            })
    }

    try {
        $Table = Get-CippTable -tablename 'templates'
        $Entity = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'TeamsPolicyTemplate' and RowKey eq '$ID'"
        if (-not $Entity) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::NotFound
                    Body       = @{ Results = "No Teams policy template with GUID $ID." }
                })
        }
        $Name = ($Entity.JSON | ConvertFrom-Json).name
        Remove-CIPPAzDataTableEntity -Force @Table -Entity $Entity

        $Result = "Deleted Teams policy template '$Name' ($ID). Tenants it was deployed to keep their settings."
        Write-LogMessage -headers $Headers -API $APIName -message $Result -Sev 'Info'
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = $Result } })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to delete Teams policy template: $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -message $Result -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = $Result } })
    }
}
