Function Invoke-ListPrinterReport {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Endpoint.Printer.Read
    .DESCRIPTION
        Universal Print readiness and usage per tenant: whether the tenant is licensed for Universal Print, how many printers, shares and connectors are registered, how many printers CIPP has catalogued, and pages printed over the reporting window. Pass tenantFilter=AllTenants for the cross-tenant view.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    # Both service plans that carry Universal Print entitlement. Business Premium ships
    # UNIVERSAL_PRINT_01, so most SMB tenants are already entitled.
    $UPServicePlans = @('795f6fe0-cc4d-4773-b050-5dde4dc704c9', 'b67adbaf-a096-42c9-967e-5a84edbe0086')

    try {
        $Tenants = if ($TenantFilter -eq 'AllTenants' -or [string]::IsNullOrWhiteSpace($TenantFilter)) {
            Get-Tenants
        } else {
            @(Get-Tenants -TenantFilter $TenantFilter)
        }

        $CatalogTable = Get-CIPPTable -TableName 'PrinterCatalog'

        $Results = foreach ($Tenant in $Tenants) {
            $Domain = $Tenant.defaultDomainName
            $Row = [ordered]@{
                Tenant               = $Tenant.displayName
                tenantFilter         = $Domain
                UniversalPrintLicensed = $false
                LicensedSeats        = 0
                PrintersRegistered   = $null
                SharesRegistered     = $null
                ConnectorsRegistered = $null
                CatalogEntries       = 0
                PagesPrinted         = $null
                Errors               = ''
            }
            $Issues = [System.Collections.Generic.List[string]]::new()

            # Entitlement comes from the tenant's own SKUs, and works app-only, so it is
            # reported even when the Universal Print APIs themselves are unavailable.
            try {
                $Skus = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/subscribedSkus' -tenantid $Domain -AsApp $true
                $UPSkus = $Skus | Where-Object { $_.servicePlans.servicePlanId | Where-Object { $_ -in $UPServicePlans } }
                if ($UPSkus) {
                    $Row.UniversalPrintLicensed = $true
                    $Row.LicensedSeats = ($UPSkus | Measure-Object -Property { $_.prepaidUnits.enabled } -Sum).Sum
                }
            } catch {
                $Issues.Add('licences')
            }

            # Everything below is Universal Print, which is delegated-only and needs the GDAP
            # Printer Administrator role; a tenant without it reports null rather than zero, so a
            # permissions gap is never mistaken for "this customer has no printers".
            try { $Row.PrintersRegistered = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/print/printers' -tenantid $Domain).Count } catch { $Issues.Add('printers') }
            try { $Row.SharesRegistered = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/print/shares' -tenantid $Domain).Count } catch { $Issues.Add('shares') }
            try { $Row.ConnectorsRegistered = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/print/connectors' -tenantid $Domain).Count } catch { $Issues.Add('connectors') }

            try {
                $Usage = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/reports/dailyPrintUsageByPrinter' -tenantid $Domain)
                $Row.PagesPrinted = ($Usage | Measure-Object -Property pageCount -Sum).Sum
            } catch {
                $Issues.Add('usage')
            }

            try {
                $CustomerId = $Tenant.customerId ?? $Domain
                $Row.CatalogEntries = @(Get-CIPPAzDataTableEntity @CatalogTable -Filter "PartitionKey eq '$CustomerId'").Count
            } catch {
                $Issues.Add('catalogue')
            }

            if ($Issues.Count -gt 0) {
                $Row.Errors = "Could not read: $($Issues -join ', '). Universal Print is delegated-only and needs the GDAP Printer Administrator role."
            }

            [PSCustomObject]$Row
        }
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        $StatusCode = [HttpStatusCode]::InternalServerError
        $Results = $ErrorMessage
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @($Results)
        })
}
