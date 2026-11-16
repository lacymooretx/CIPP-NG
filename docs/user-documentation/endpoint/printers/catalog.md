# Printer Catalogue

Holds every printer CIPP manages for a client, and deploys them to devices through Intune. Aspendora fork addition. A catalogue entry is one of three types:

| Type | What it needs | How it is deployed |
| --- | --- | --- |
| Universal Print | The Universal Print share ID. A share name is optional, for display. | An Intune settings catalog policy named `CIPP: Universal Print - <name>`. It is user-scoped: assign it to users, not devices. |
| Direct IP | A host address (IP or DNS name), a port (default 9100) and a driver name as it appears in the driver store. | An Intune platform script named `CIPP: Printer - <name>`, run as system. |
| Print server share | A UNC path (`\\server\queue`). | An Intune platform script named `CIPP: Printer - <name>`, run as the signed-in user, because a mapped queue lives in the user's profile. |

Intune has no setting for TCP/IP printers or mapped print-server queues, so those two types are deployed as a generated PowerShell script. The script is safe to run again on a device that already has the printer.

The catalogue is stored in CIPP (the `PrinterCatalog` table), keyed on the tenant's ID, so renaming the tenant's default domain does not lose it.

## Adding or editing a printer

Select **Add Printer**, or **Edit** on a row. The form asks for the tenant, the printer name and type, the fields for that type, and optionally a location, a group to assign to and a comment. CIPP checks the fields for the chosen type when you save, so an incomplete entry is refused here rather than failing on a device later.

For a direct IP printer, **Driver source** says where the driver comes from:

* **Inbox driver**: shipped with Windows.
* **Staged by an Intune Win32 app**: you deploy the driver separately.
* **Stage from an INF path**: the script stages the driver with `pnputil` from an INF path on the device. The path is required.

## Columns

**Name**, **Printer type**, **Host address**, **UNC path**, **Share name**, **Location** and **Last deployed**. Select a row to see the whole entry.

## Actions

| Action | What it does |
| --- | --- |
| Deploy to Intune | Creates or updates the policy or script for the printer, and assigns it to a group if one is given. Leave the group blank to use the one stored on the entry. A group can be a display name or an object ID. Deploying again updates the same policy or script, matched by name, rather than adding another. Sets **Last deployed**. |
| Document in Hudu | Writes the tenant's whole catalogue to its Hudu company as the article **Printers (CIPP-managed)**, then reads it back. Running it again updates the same article. Needs the Hudu extension enabled and the tenant mapped to a Hudu company; otherwise it says which is missing. (Replaced the IT Glue action on 2026-11-15: IT Glue is a read-only archive.) |
| Edit | Opens the entry in the form. |
| Remove from catalogue | Deletes the CIPP record only. Printers already installed on devices, and the Intune policy or script, are left alone. |

## Standard

The **Deploy the tenant's printer catalogue** standard (`PrinterCatalog`) compares the catalogue with what is deployed in Intune and reports any printer with no matching policy or script. Remediation deploys the missing ones the same way as **Deploy to Intune**. Turn on **Apply the group assignment stored on each catalogue entry** to assign them as well. The standard never removes printers.

## Permissions

Viewing needs `Endpoint.Printer.Read`. Adding, editing, removing, deploying and writing to Hudu need `Endpoint.Printer.ReadWrite`.

## API

* `GET /api/ListPrinterCatalog?tenantFilter=<tenant>`
* `POST /api/AddPrinterCatalogEntry`: `Name`, `PrinterType` (`UniversalPrint`, `DirectIP` or `ServerShare`) and the fields for that type. Include `id` to edit an existing entry.
* `POST /api/RemovePrinterCatalogEntry`: `id`.
* `POST /api/ExecDeployCatalogPrinter`: `id`, and optionally `AssignTo`.
* `POST /api/ExecPrinterCatalogToITGlue`
