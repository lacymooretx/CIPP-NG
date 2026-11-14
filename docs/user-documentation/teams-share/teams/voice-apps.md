# Voice Apps & Assignments

Reads the Teams voice apps and assignment data that live outside the Teams policy types: call queues, auto attendants, schedules, resource accounts, emergency locations and group policy assignments. Aspendora fork addition. Both pages are read only. For policies, see [Teams Policies](policies.md).

## Routes

**Voice Apps & Assignments** lists 13 routes from CIPP's built-in route map (`Config/TeamsVoiceAppRoutes.json`). The list is the same for every tenant and loads without calling the tenant.

| Column | Shows |
| --- | --- |
| Key | The route name, for example `CallQueues`. |
| Category | Voice apps, Voice, Assignment or Tenant. |
| Verified | 200 when a live read of the route was confirmed to work. Blank when the route has not been tested. |
| Path | The ConfigAPI path the route reads. |
| Description | What the route returns. |

| Category | Routes |
| --- | --- |
| Voice apps | CallQueues, AutoAttendants, Schedules, ComplianceRecording, SharedCallQueueHistory, ApplicationInstanceAssociations, SupportedLanguages, SupportedTimezones |
| Voice | ResourceAccounts, EmergencyLocations |
| Assignment | GroupPolicyAssignments, AssignmentOperations |
| Tenant | ServiceDiscovery |

## Viewing a route

**View in tenant** opens the route for the selected tenant and lists what it returns, for example every call queue with its routing, overflow, timeout, agent and voicemail settings. The columns come from the response, because each route returns a different shape. **Back to routes** returns to the list.

## Where the data comes from

The data is read live from the Teams admin configuration API (ConfigAPI) with a delegated token. ConfigAPI is not documented by Microsoft, and which routes work varies by tenant, so a route can fail or return nothing.

There is no route for per-user policy assignments. The customer-facing ConfigAPI has none, and the remote PowerShell path the Teams module uses for them is refused under GDAP. Group policy assignments are available.

## Permissions

The pages need `Teams.Voice.Read`.

## API

`GET /api/ListTeamsVoiceApp` with:

* `Catalog=true`: the route map only, no tenant call. Add `Category` to filter it.
* `TenantFilter` and `Route` (a route key): that route's data. Add `Identity` for one object.
* `TenantFilter` only: reads every route, one call each, and reports errors per route.
* `AsApp=true` to use an application token instead of a delegated one.

An unknown route key returns 400.
