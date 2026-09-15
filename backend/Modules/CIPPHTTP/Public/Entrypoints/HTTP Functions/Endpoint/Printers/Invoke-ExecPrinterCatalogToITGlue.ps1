Function Invoke-ExecPrinterCatalogToITGlue {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.ReadWrite
    .DESCRIPTION
        Writes a tenant's CIPP printer catalogue into IT Glue as a document, so the printers a client has are documented where the service desk already looks. Re-running updates the same document rather than creating another.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter

    $DocumentName = 'Printers (CIPP-managed)'

    try {
        # Same read the rest of the extension code uses: the Extensionsconfig table holds one
        # row whose 'config' column is the whole integrations blob as JSON.
        $ConfigTable = Get-CIPPTable -TableName Extensionsconfig
        $Configuration = (Get-CIPPAzDataTableEntity @ConfigTable).config | ConvertFrom-Json -Depth 10 -ErrorAction SilentlyContinue
        if ($Configuration.ITGlue.Enabled -ne $true) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{ 'Results' = 'The IT Glue extension is not enabled in CIPP settings.' }
                })
        }

        # An unmapped tenant must be surfaced, not swallowed: silently writing nothing looks
        # identical to a client with no printers.
        $Org = Get-ITGlueOrganizationId -TenantFilter $TenantFilter
        if (-not $Org) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{ 'Results' = "Tenant $TenantFilter is not mapped to an IT Glue organisation. Map it under Settings > Integrations > IT Glue." }
                })
        }

        $Tenant = Get-Tenants -TenantFilter $TenantFilter
        $CustomerId = $Tenant.customerId ?? $TenantFilter
        $Table = Get-CIPPTable -TableName 'PrinterCatalog'
        $Catalog = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$CustomerId'")

        Connect-ITGlueAPI -Configuration $Configuration

        # HTML-encode every catalogue value: printer names and locations are operator free text
        # and this is being spliced into an HTML document body.
        function ConvertTo-CIPPHtmlText {
            param($Value)
            if ($null -eq $Value -or "$Value" -eq '') { return '' }
            return [System.Net.WebUtility]::HtmlEncode([string]$Value)
        }

        if ($Catalog.Count -eq 0) {
            $Body = '<p>No printers are catalogued in CIPP for this client.</p>'
        } else {
            $Rows = foreach ($P in ($Catalog | Sort-Object Name)) {
                $Detail = switch ($P.PrinterType) {
                    'UniversalPrint' { "Share ID: $(ConvertTo-CIPPHtmlText $P.ShareId)" }
                    'DirectIP' { "$(ConvertTo-CIPPHtmlText $P.HostAddress):$(if ($P.PortNumber) { ConvertTo-CIPPHtmlText $P.PortNumber } else { '9100' }) &mdash; driver: $(ConvertTo-CIPPHtmlText $P.DriverName)" }
                    'ServerShare' { ConvertTo-CIPPHtmlText $P.UNCPath }
                    default { '' }
                }
                "<tr><td>$(ConvertTo-CIPPHtmlText $P.Name)</td><td>$(ConvertTo-CIPPHtmlText $P.PrinterType)</td><td>$Detail</td><td>$(ConvertTo-CIPPHtmlText $P.Location)</td><td>$(ConvertTo-CIPPHtmlText $P.LastDeployed)</td></tr>"
            }
            $Body = @"
<p>Maintained automatically by CIPP. Edit printers in CIPP (Intune &gt; Printers &gt; Printer Catalogue), not here &mdash; changes made in IT Glue are overwritten on the next sync.</p>
<table>
<thead><tr><th>Printer</th><th>Type</th><th>Target</th><th>Location</th><th>Last deployed (UTC)</th></tr></thead>
<tbody>
$($Rows -join "`n")
</tbody>
</table>
<p>Generated $((Get-Date).ToUniversalTime().ToString('u')).</p>
"@
        }

        # Converge on the document name so a re-sync updates rather than duplicating.
        $Existing = $null
        try {
            $Docs = Invoke-ITGlueRequest -Path "/organizations/$($Org.OrganizationId)/relationships/documents" -Method GET -AllPages
            $Existing = $Docs | Where-Object { $_.attributes.name -eq $DocumentName } | Select-Object -First 1
        } catch {
            $Existing = $null
        }

        if ($Existing) {
            $Payload = @{ data = @{ type = 'documents'; attributes = @{ name = $DocumentName; content = $Body } } }
            $null = Invoke-ITGlueRequest -Path "/organizations/$($Org.OrganizationId)/relationships/documents/$($Existing.id)" -Method PATCH -Body $Payload
            $Verb = 'Updated'
        } else {
            $Payload = @{ data = @{ type = 'documents'; attributes = @{ name = $DocumentName; content = $Body } } }
            $null = Invoke-ITGlueRequest -Path "/organizations/$($Org.OrganizationId)/relationships/documents" -Method POST -Body $Payload
            $Verb = 'Created'
        }

        $Result = "$Verb '$DocumentName' in IT Glue organisation $($Org.OrganizationName) with $($Catalog.Count) printer(s)."
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Info'
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to write the printer catalogue to IT Glue. $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ 'Results' = $Result }
        })
}
