Function Invoke-ExecPrinterCatalogToHudu {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Printer.ReadWrite
    .DESCRIPTION
        Writes a tenant's CIPP printer catalogue into Hudu as the article 'Printers (CIPP-managed)' in the mapped company, so the printers a client has are documented where the service desk already looks. Re-running updates the same article (matched by exact name) and reads it back. Replaces ExecPrinterCatalogToITGlue: IT Glue has been a read-only archive since 2026-10-11 (Aspendora fork, CIPP-64).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter

    $DocumentName = 'Printers (CIPP-managed)'

    try {
        $ConfigTable = Get-CIPPTable -TableName Extensionsconfig
        $Configuration = (Get-CIPPAzDataTableEntity @ConfigTable).config | ConvertFrom-Json -Depth 10 -ErrorAction SilentlyContinue
        if ($Configuration.Hudu.Enabled -ne $true) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{ 'Results' = 'The Hudu extension is not enabled in CIPP settings.' }
                })
        }

        # An unmapped tenant must be surfaced, not swallowed: silently writing nothing looks
        # identical to a client with no printers.
        $Company = Get-HuduCompanyId -TenantFilter $TenantFilter
        if (-not $Company) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{ 'Results' = "Tenant $TenantFilter is not mapped to a Hudu company. Map it under Settings > Integrations > Hudu > Mappings." }
                })
        }

        $Tenant = Get-Tenants -TenantFilter $TenantFilter
        $CustomerId = $Tenant.customerId ?? $TenantFilter
        $Table = Get-CIPPTable -TableName 'PrinterCatalog'
        $Catalog = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$CustomerId'")

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
<p>Maintained automatically by CIPP. Edit printers in CIPP (Intune &gt; Printers &gt; Printer Catalogue), not here &mdash; changes made in Hudu are overwritten on the next sync.</p>
<table>
<thead><tr><th>Printer</th><th>Type</th><th>Target</th><th>Location</th><th>Last deployed (UTC)</th></tr></thead>
<tbody>
$($Rows -join "`n")
</tbody>
</table>
<p>Generated $((Get-Date).ToUniversalTime().ToString('u')).</p>
"@
        }

        # Converge on the article name so a re-sync updates rather than duplicating. Hudu ignores
        # unknown query parameters, so match the name client-side.
        $Listed = @((Invoke-CippHuduRequest -Configuration $Configuration -Resource '/articles' -Params @{ company_id = $Company.CompanyId; name = $DocumentName; page_size = 100 }).articles |
                Where-Object { $_.name -eq $DocumentName -and [string]$_.company_id -eq [string]$Company.CompanyId -and -not $_.archived })
        if ($Listed.Count -gt 1) { throw "$($Listed.Count) articles named '$DocumentName' in this Hudu company. Archive the extras by hand." }
        $Payload = @{ article = @{ name = $DocumentName; content = $Body; company_id = [int]$Company.CompanyId } }
        $Saved = if ($Listed.Count -eq 1) {
            (Invoke-CippHuduRequest -Configuration $Configuration -Method PUT -Resource "/articles/$($Listed[0].id)" -Body $Payload).article
        } else {
            (Invoke-CippHuduRequest -Configuration $Configuration -Method POST -Resource '/articles' -Body $Payload).article
        }
        $Verb = if ($Listed.Count -eq 1) { 'Updated' } else { 'Created' }
        # Read back: a 2xx is not proof the write applied.
        $Back = (Invoke-CippHuduRequest -Configuration $Configuration -Resource "/articles/$($Saved.id)").article
        if ($Back.name -ne $DocumentName -or [string]$Back.company_id -ne [string]$Company.CompanyId -or $Back.content -notmatch 'Maintained automatically by CIPP') {
            throw "Read-back of Hudu article $($Saved.id) did not match what was written."
        }

        $Result = "$Verb '$DocumentName' in Hudu company $($Company.CompanyName) with $($Catalog.Count) printer(s) (article $($Saved.id))."
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Info'
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to write the printer catalogue to Hudu. $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ 'Results' = $Result }
        })
}
