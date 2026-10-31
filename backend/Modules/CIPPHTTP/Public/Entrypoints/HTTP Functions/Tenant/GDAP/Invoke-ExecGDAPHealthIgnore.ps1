function Invoke-ExecGDAPHealthIgnore {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Tenant.Relationship.ReadWrite
    .SYNOPSIS
        Ignore (or stop ignoring) a GDAP customer in the GDAP health check
    .DESCRIPTION
        Action=Ignore   stops the GDAP health check reporting anything for the customer's relationships
                        (for a former customer, or one we never manage). Name and Reason are recorded.
        Action=Unignore reports on the customer again.
        Action=List     (default) lists ignored customers.
        Open findings for the customer clear on the next check. Nothing in Partner Center changes.
        Aspendora fork addition (Vikunja CIPP-2).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $Headers = $Request.Headers
    $Action = [string]($Request.Body.Action ?? $Request.Query.Action ?? 'List')
    $TenantId = [string]($Request.Body.TenantId ?? $Request.Query.TenantId)
    $Name = [string]($Request.Body.Name ?? $Request.Query.Name)
    $Reason = [string]($Request.Body.Reason ?? $Request.Query.Reason)
    $Table = Get-CIPPTable -tablename 'GDAPHealthState'

    if ($Action -ne 'List' -and $TenantId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'TenantId must be the customer tenant id (a GUID).' } })
    }

    try {
        switch ($Action) {
            'Ignore' {
                # API clients have no client principal header.
                $User = try { ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Headers.'x-ms-client-principal')) | ConvertFrom-Json).userDetails } catch { 'API client' }
                Add-CIPPAzDataTableEntity @Table -Entity @{
                    PartitionKey = 'Ignore'
                    RowKey       = $TenantId.ToLower()
                    Name         = $Name
                    Reason       = $Reason
                    IgnoredBy    = [string]($User ?? 'unknown')
                    IgnoredUtc   = (Get-Date).ToUniversalTime().ToString('o')
                } -Force
                Write-LogMessage -headers $Headers -API 'GDAP Health' -tenant 'Global' -message "GDAP health check now ignores $(if ($Name) { "$Name " })($TenantId). Reason: $Reason" -Sev 'Info'
                $Results = "GDAP health check will ignore $(if ($Name) { $Name } else { $TenantId }). Its findings clear at the next check."
            }
            'Unignore' {
                $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Ignore' and RowKey eq '$($TenantId.ToLower())'"
                if ($Row) { Remove-AzDataTableEntity @Table -Entity $Row -Force }
                Write-LogMessage -headers $Headers -API 'GDAP Health' -tenant 'Global' -message "GDAP health check reports on $TenantId again." -Sev 'Info'
                $Results = "GDAP health check will report on $TenantId again from the next check."
            }
            'List' {
                $Results = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Ignore'" | ForEach-Object {
                        [pscustomobject]@{ TenantId = $_.RowKey; Name = $_.Name; Reason = $_.Reason; IgnoredBy = $_.IgnoredBy; IgnoredUtc = $_.IgnoredUtc }
                    })
            }
            default {
                return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = "Unknown Action '$Action'. Use Ignore, Unignore or List." } })
            }
        }
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $StatusCode = [HttpStatusCode]::InternalServerError
        $Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)"
    }
    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = @{ Results = $Results } })
}
