# Autopatch

Shows and manages a tenant's Windows Autopatch update management: deployment audiences, update policies and which Windows devices are enrolled. Aspendora fork addition. Select a single tenant; All Tenants is not supported.

## Where the data comes from

The page reads the Windows Update for Business deployment service in Graph (beta `admin/windows/updates`): update policies, deployment audiences with their members and exclusions, and enrolled updatable assets. It joins those to the tenant's Intune managed devices, so Windows devices that are not enrolled are listed too. Everything is read live with CIPP's application token. **Refresh** reads it again.

The SAM app needs the `WindowsUpdates.ReadWrite.All` application permission in the tenant. If the page returns 403, refresh the tenant's CPV permissions.

Only two update categories are supported: **Driver** and **Quality**. Every action defaults to both.

## Tiles

**Policies**, **Audiences**, **Assets** (enrolled devices), **Windows Devices** (Intune managed Windows devices with an Entra device ID) and **Unenrolled**.

## Tables

| Table | Columns | Actions |
| --- | --- | --- |
| Deployment Audiences | Audience ID, members, exclusions, number of policies, categories | None |
| Update Policies | Policy ID, audience ID, categories, created | **Delete Policy**, after a confirmation |
| Enrollment Status | Device name, enrolled, enrollment categories, Entra device ID, user, OS version, last sync | **Enroll Device** (unenrolled rows) and **Unenroll Device** (enrolled rows), for the categories you choose |

Select a row to see the raw Graph object.

## Buttons

| Button | What it does |
| --- | --- |
| Onboard Tenant | Splits the tenant's Windows managed devices into three rings by the first character of their Entra device ID: 0-1 go to **Test**, 2-7 to **Ring 1** and 8-f to **Last**. For each ring that has devices it creates a deployment audience, adds the devices, enrolls them in the chosen categories and creates one update policy per category. If the tenant already has Autopatch policies, audiences or enrolled devices, it stops with a conflict; turn on **Force** to add another set anyway. |
| Add Ring | Creates one deployment audience for the devices you list, adds them, enrolls them and creates one update policy per category. At least one device is required. The ring name is only used in the result and the log; Graph audiences have no name. |
| Enroll Assets | Enrolls the devices you list in the chosen categories, without creating an audience or policy. |

Device lists take one entry per line. An entry can be an Entra device ID, an Intune device ID, a device name or a serial number; CIPP looks it up among the tenant's Windows managed devices and uses its Entra device ID. An entry that matches no device is sent as given.

## Permissions

Viewing needs `Endpoint.MEM.Read`. Onboarding, adding rings, enrolling, unenrolling and deleting policies need `Endpoint.MEM.ReadWrite`.

## API

* `GET /api/ListWindowsAutopatch?tenantFilter=<tenant>&includeManagedDevices=true&includeAudienceMembers=true`
* `GET /api/ListAutopatchEnrollmentStatus?tenantFilter=<tenant>`. Add `includeUnenrolled=false` to list only enrolled devices, or `deviceIds` to filter.
* `POST /api/ExecAutopatchOnboard`: `categories`, `force`.
* `POST /api/AddAutopatchRing`: `ringName`, `deviceIds`, `categories`.
* `POST /api/EnrollAutopatchAsset` and `POST /api/ExecAutopatchUnenroll`: `deviceIds`, `categories`.
* `POST /api/RemoveAutopatchPolicy`: `policyId`.
