# Print Connectors

Lists the Universal Print connectors registered in the selected tenant. A connector is the on-premises service that links printers without native Universal Print support to the cloud. Aspendora fork addition. The page is read only.

## Columns

**Display name**, **Fully qualified domain name**, **Operating system**, **App version** and **Registered**. Select a row to see the full connector record from Graph.

## Where the data comes from

Graph `GET /v1.0/print/connectors`, read live with a delegated token. Universal Print does not support GDAP access, so in most tenants this page returns an error that explains why. See the warning on [Universal Print Printers](README.md).

## Permissions

The page needs `Endpoint.Printer.Read`.

## API

`GET /api/ListPrintConnectors?tenantFilter=<tenant>`
