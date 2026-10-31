function Invoke-ExecDeleteGDAPRelationship {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Tenant.Relationship.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers


    # Interact with query parameters or the body of the request.
    $GDAPId = $Request.Query.GDAPId ?? $Request.Body.GDAPId
    try {
        # Aspendora fork: an invite the customer never accepted (status 'created') cannot be terminated;
        # Graph only allows deleting it, and a delete needs the relationship's current ETag.
        $Relationship = New-GraphGetRequest -NoAuthCheck $true -uri "https://graph.microsoft.com/beta/tenantRelationships/delegatedAdminRelationships/$($GDAPId)" -tenantid $env:TenantID
        if ($Relationship.status -eq 'created') {
            $null = New-GraphPostRequest -NoAuthCheck $true -uri "https://graph.microsoft.com/beta/tenantRelationships/delegatedAdminRelationships/$($GDAPId)" -type DELETE -tenantid $env:TenantID -AddedHeaders @{ 'If-Match' = $Relationship.'@odata.etag' }
            # Microsoft accepts the DELETE but has been seen to leave the invite in 'created' for a while
            # afterwards (2026-10-31), so report the request, not the outcome.
            $Result = "Delete requested for unaccepted GDAP invite $($Relationship.displayName) ($($GDAPId)). Microsoft accepted it; it can take a while to disappear from the list."
        } else {
            $null = New-GraphPostRequest -NoAuthCheck $True -uri "https://graph.microsoft.com/beta/tenantRelationships/delegatedAdminRelationships/$($GDAPId)/requests" -type POST -body '{"action":"terminate"}' -tenantid $env:TenantID
            $Result = "Success. GDAP relationship for $($GDAPId) been revoked"
        }
        Write-LogMessage -headers $Headers -API $APIName -message $Result -Sev 'Info'
        $StatusCode = [HttpStatusCode]::OK

    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to revoke GDAP relationship for $($GDAPId). Error: $($ErrorMessage.NormalizedError)"
        $StatusCode = [HttpStatusCode]::InternalServerError
        Write-LogMessage -headers $Headers -API $APIName -message $Result -Sev 'Error' -LogData $ErrorMessage
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ 'Results' = $Result }
        })

}
