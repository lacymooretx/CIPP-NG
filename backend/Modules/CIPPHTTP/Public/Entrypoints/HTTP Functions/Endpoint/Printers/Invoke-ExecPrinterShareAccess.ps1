Function Invoke-ExecPrinterShareAccess {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.ReadWrite
    .DESCRIPTION
        Grants or revokes access to a Universal Print printer share for a user or a group.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $ShareId = $Request.Body.ShareId
    # The UI autocomplete posts a {label, value} object; a scripted caller posts a bare id.
    $PrincipalId = $Request.Body.PrincipalId.value ?? $Request.Body.PrincipalId
    $PrincipalName = $Request.Body.PrincipalName ?? $Request.Body.PrincipalId.label ?? $PrincipalId
    $PrincipalType = $Request.Body.PrincipalType ?? 'User'
    $Action = $Request.Body.Action ?? 'Add'

    # Answer a missing field as a 400 rather than letting the throw surface as a bare 500.
    if (!$ShareId -or !$PrincipalId) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ 'Results' = 'You must supply both a ShareId and a PrincipalId' }
            })
    }

    # allowedUsers is keyed by user object, allowedGroups by group object; the collection name and
    # the $ref target differ, so resolve both from the principal type rather than guessing.
    switch ($PrincipalType) {
        'Group' {
            $Collection = 'allowedGroups'
            $RefTarget = 'groups'
        }
        default {
            $Collection = 'allowedUsers'
            $RefTarget = 'users'
        }
    }

    try {
        # Delegated only - Universal Print rejects app-only tokens. See Invoke-ListPrinters.
        if ($Action -eq 'Remove') {
            $Uri = "https://graph.microsoft.com/v1.0/print/shares/$ShareId/$Collection/$PrincipalId/`$ref"
            $null = New-GraphPOSTRequest -uri $Uri -tenantid $TenantFilter -type 'DELETE'
            $Result = "Revoked access to printer share $ShareId for $PrincipalName"
        } else {
            $Uri = "https://graph.microsoft.com/v1.0/print/shares/$ShareId/$Collection/`$ref"
            $Body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/$RefTarget/$PrincipalId" } | ConvertTo-Json -Compress
            $null = New-GraphPOSTRequest -uri $Uri -tenantid $TenantFilter -type 'POST' -body $Body
            $Result = "Granted access to printer share $ShareId for $PrincipalName"
        }
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Info'
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to update access on printer share $ShareId for $PrincipalName. $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ 'Results' = $Result }
        })
}
