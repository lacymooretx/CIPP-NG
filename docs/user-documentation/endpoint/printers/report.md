# Printer Readiness & Usage

Shows, for every tenant, whether it is licensed for Universal Print, what is registered, how many printers CIPP has catalogued and how many pages were printed. Aspendora fork addition. The page always covers all tenants and is read only.

## Columns

| Column | Shows |
| --- | --- |
| Tenant | The tenant's display name. |
| Universal Print licensed | Whether any of the tenant's subscriptions includes a Universal Print service plan. Business Premium includes one, so most small business tenants are already licensed. |
| Licensed seats | Enabled units on those subscriptions. |
| Printers registered | Universal Print printers in the tenant. |
| Shares registered | Universal Print shares. |
| Connectors registered | Universal Print connectors. |
| Catalog entries | Printers in the tenant's CIPP [Printer Catalogue](catalog.md). |
| Pages printed | Total pages from Microsoft's daily print usage report. |
| Errors | What could not be read. |

## Where the data comes from

Everything is read live when the page loads, one tenant at a time, so the page can take a while with many tenants.

* Licensing is read from the tenant's subscribed SKUs with an application token, so it is shown even when Universal Print itself cannot be read.
* Printers, shares, connectors and pages printed are Universal Print data. Universal Print accepts only delegated access and needs the Printer Administrator role. When it cannot be read, the count is left blank rather than shown as zero, so a permissions gap is not mistaken for a client with no printers, and **Errors** lists what failed. See the warning on [Universal Print Printers](README.md).
* Catalogue entries come from CIPP's own table.

## Permissions

The page needs `Endpoint.Printer.Read`.

## API

`GET /api/ListPrinterReport?tenantFilter=AllTenants`. A single tenant can be passed instead.
