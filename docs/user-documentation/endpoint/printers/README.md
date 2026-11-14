# Universal Print Printers

Lists the Universal Print printers registered in the selected tenant. Aspendora fork addition, part of the **Intune > Printers** menu. The page is read only.

## Columns

**Display name**, **Manufacturer**, **Model**, **Shared**, **Accepting jobs**, **Status** and **Registered**. Select a row to see the full printer record from Graph.

## Where the data comes from

Graph `GET /v1.0/print/printers`, read live with a delegated token.

{% hint style="warning" %}
Universal Print does not support partner delegated (GDAP) access. It is not on Microsoft's GDAP supported-workloads list, its Graph APIs have no application permissions, and the GDAP identity cannot hold the Universal Print licence the service needs. In most tenants this page therefore returns an error, which CIPP rewrites to explain this rather than showing Microsoft's "required security scopes" message. Manage Universal Print printers in the customer tenant directly. CIPP can still **deploy** Universal Print printers to users through the [Printer Catalogue](catalog.md).
{% endhint %}

## Other printer pages

| Page | What it is for |
| --- | --- |
| [Printer Catalogue](catalog.md) | The printers CIPP manages for a client, and deploying them through Intune. |
| [Printer Shares](shares.md) | Universal Print shares, and who may print to them. |
| [Print Connectors](connectors.md) | Universal Print connectors registered in the tenant. |
| [Deployment Status](deployment-status.md) | Per-device install results for printers CIPP deployed as scripts. |
| [Readiness & Usage](report.md) | Universal Print licensing, counts and pages printed, for all tenants. |

## Permissions

The printer pages need `Endpoint.Printer.Read`. Actions that change something need `Endpoint.Printer.ReadWrite`.

## API

`GET /api/ListPrinters?tenantFilter=<tenant>`. An authorization failure returns 403 with the explanation above.
