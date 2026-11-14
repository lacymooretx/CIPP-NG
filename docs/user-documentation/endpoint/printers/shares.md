# Printer Shares

Lists the Universal Print printer shares in the selected tenant, and grants or removes print access to them. Aspendora fork addition.

## Columns

**Display name**, **Allow all users**, **Accepting jobs**, **Status** and **Created**. Select a row to see the full share record from Graph.

When the signed-in identity is not a Printer Administrator, Graph returns only the ID, name, manufacturer, model and location of each share. A sparse row means missing rights, not an empty share.

## Actions

| Action | What it does |
| --- | --- |
| Grant access to user | Adds a user to the share's allowed users. |
| Grant access to group | Adds a group to the share's allowed groups. |
| Revoke user access | Removes a user from the share's allowed users. |

Each action asks you to pick the user or group and confirm. The page has no action to revoke a group.

## Where the data comes from

Graph `/v1.0/print/shares`, read and changed live with a delegated token. Universal Print does not support GDAP access, so in most tenants this page returns an error that explains why. See the warning on [Universal Print Printers](README.md).

## Permissions

Viewing needs `Endpoint.Printer.Read`. Granting and revoking need `Endpoint.Printer.ReadWrite`.

## API

* `GET /api/ListPrinterShares?tenantFilter=<tenant>`. Add `ShareId` to read one share with its allowed users and groups.
* `POST /api/ExecPrinterShareAccess`: `ShareId`, `PrincipalId`, `PrincipalType` (`User` or `Group`) and `Action` (`Add` or `Remove`).
