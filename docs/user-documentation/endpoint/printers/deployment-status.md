# Printer Deployment Status

Shows, per device, whether the printers CIPP deployed as Intune platform scripts installed. Aspendora fork addition. The page is read only.

It covers direct IP and print-server printers from the [Printer Catalogue](catalog.md), which are deployed as scripts named `CIPP: Printer - <name>`. Universal Print printers are deployed as settings catalog policies and are not listed here; check those in Intune.

## Columns

| Column | Shows |
| --- | --- |
| Printer | The catalogue printer name, taken from the script name. |
| Device name | The managed device. |
| Run state | Intune's run state for the script on that device, such as success or fail. |
| Error code | Intune's error code. |
| Last state update | When the device last reported. |
| Message | What the script wrote as its result, cut to 500 characters. For a failure this is usually the reason. |

The **Failures only** filter shows rows whose run state is fail.

## Where the data comes from

Graph beta `deviceManagement/deviceManagementScripts`, filtered to scripts whose name starts with `CIPP: Printer - `, and each script's `deviceRunStates`, read live. Scripts that were created outside CIPP are not shown.

## Permissions

The page needs `Endpoint.Printer.Read`.

## API

`GET /api/ListPrinterDeploymentStatus?tenantFilter=<tenant>`
