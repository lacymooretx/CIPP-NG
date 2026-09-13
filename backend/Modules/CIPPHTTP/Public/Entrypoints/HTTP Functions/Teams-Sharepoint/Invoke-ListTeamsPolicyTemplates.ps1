function Invoke-ListTeamsPolicyTemplates {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Teams.Config.Read
    .DESCRIPTION
        Lists saved Teams policy templates. Pass ID to return one template in full,
        including every captured policy and its parameters.

        Without ID the policy bodies are omitted - a full baseline template carries
        thousands of properties and the list view only needs the summary.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $ID = $Request.Query.ID ?? $Request.Body.ID

    $Table = Get-CippTable -tablename 'templates'
    $Filter = "PartitionKey eq 'TeamsPolicyTemplate'"
    $Templates = (Get-CIPPAzDataTableEntity @Table -Filter $Filter) | ForEach-Object {
        $GUID = $_.RowKey
        $Data = $_.JSON | ConvertFrom-Json
        $Data | Add-Member -NotePropertyName 'GUID' -NotePropertyValue $GUID -Force
        $Data
    }

    if ($ID) {
        $Templates = $Templates | Where-Object { $_.GUID -eq $ID }
    } else {
        # Summary view: drop the policy bodies, keep which types are in each template.
        $Templates = $Templates | ForEach-Object {
            [pscustomobject]@{
                GUID            = $_.GUID
                name            = $_.name
                description     = $_.description
                capturedFrom    = $_.capturedFrom
                capturedAt      = $_.capturedAt
                policyCount     = $_.policyCount
                policyTypes     = @($_.policies.PolicyType)
                captureFailures = @($_.captureFailures).Count
            }
        }
    }

    return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = @($Templates)
        })
}
