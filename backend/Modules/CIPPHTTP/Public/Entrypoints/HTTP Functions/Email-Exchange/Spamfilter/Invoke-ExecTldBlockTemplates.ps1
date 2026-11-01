function Invoke-ExecTldBlockTemplates {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Exchange.SpamFilter.ReadWrite
    .SYNOPSIS
        Shows, or saves into the template library, the abused-TLD Tenant Allow/Block List templates
    .DESCRIPTION
        Action=Preview (default) returns the shipped templates (Config/TenantAllowBlockListTemplates/AbusedTlds-*.json)
        and the TLD list with false-positive risk notes. Action=Save writes them to the CIPP template library
        (templates table, PartitionKey TenantAllowBlockListTemplate) under fixed GUIDs, so saving again updates them
        in place instead of adding copies. Saving does NOT deploy anything: a template only reaches a tenant when it is
        added to a standards template with the Tenant Allow/Block List Template standard and that standard is set to
        remediate. Template=<GUID> limits Save to one template. Aspendora fork addition (Vikunja CIPP-30).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $Action = [string]($Request.Query.Action ?? $Request.Body.Action ?? 'Preview')
    $Only = [string]($Request.Query.Template ?? $Request.Body.Template)
    try {
        $Catalog = Get-CIPPAbusedTldCatalog
        if ($Action -ne 'Save') {
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = [pscustomobject]@{ Version = $Catalog.Version; Sources = $Catalog.Sources; Tlds = $Catalog.Tlds; Templates = $Catalog.Templates } })
        }

        $Table = Get-CippTable -tablename 'templates'
        $Table.Force = $true
        $Results = foreach ($Template in $Catalog.Templates) {
            if ($Only -and $Template.GUID -ne $Only) { continue }
            # Same stored shape as Invoke-AddTenantAllowBlockListTemplate, plus the description.
            $JSON = [ordered]@{
                entries      = [string]$Template.entries
                listType     = [string]$Template.listType
                listMethod   = [string]$Template.listMethod
                notes        = [string]$Template.notes
                NoExpiration = $Template.NoExpiration -eq $true
                RemoveAfter  = $Template.RemoveAfter -eq $true
                templateName = [string]$Template.templateName
                description  = [string]$Template.description
            } | ConvertTo-Json -Depth 5 -Compress
            Add-CIPPAzDataTableEntity @Table -Entity @{ JSON = "$JSON"; RowKey = [string]$Template.GUID; PartitionKey = 'TenantAllowBlockListTemplate' }
            "Saved '$($Template.templateName)' ($($Template.GUID))"
        }
        $Results = @($Results)
        if ($Results.Count -eq 0) { $Results = @("No template matched '$Only'.") }
        Write-LogMessage -headers $Request.Headers -API 'ExecTldBlockTemplates' -message ($Results -join '; ') -Sev 'Info'
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = $Results } })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'ExecTldBlockTemplates' -message "Failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
