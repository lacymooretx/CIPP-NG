# Teams Policies

Lists the Microsoft Teams admin policy and configuration types CIPP can read, and shows a tenant's live instances of each. Aspendora fork addition. Both pages are read only.

## Policy types

**Teams Policies** lists 48 policy types from CIPP's built-in catalogue (`Config/TeamsPolicyTypes.json`). The list is the same for every tenant and loads without calling the tenant.

| Column | Shows |
| --- | --- |
| Type | The Teams policy type, for example `TeamsMeetingPolicy`. |
| Category | Meetings, Messaging, Apps, External access, Voice, or Client & general. |
| Identity | **Global**: one tenant-wide object only. **Named**: Global plus custom named policies (`Tag:<Name>`). This is best effort; check it per tenant. |
| Premium | The type's useful settings need a Teams Premium licence. |
| Description | What the type controls. |

## Policy instances

**View policy instances** opens the instances page for that type in the selected tenant. It lists every instance of the type, Global and any named ones, with all their settings. The columns come from the response, because each type has its own set of properties, often more than 100. **Back to policy types** returns to the list.

## Where the data comes from

The instances are read live from the Teams admin configuration API (ConfigAPI) with a delegated token. ConfigAPI is not documented by Microsoft, so a type can fail or return nothing in some tenants. The federation types (`TenantFederationSettings`, `TenantFederationConfiguration`, `TeamsAcsFederationConfiguration`) are read through Teams service discovery.

The page does not change policies. Policy changes and per-user assignments are not made from here.

## Permissions

The pages need `Teams.Config.Read`.

## API

`GET /api/ListTeamsPolicy` with:

* `Catalog=true`: the type catalogue only, no tenant call. Add `Category` to filter it.
* `TenantFilter` and `PolicyType`: every instance of one type. `PolicyType` can be the type, the cmdlet noun or the full cmdlet name (`Get-CsTeamsMeetingPolicy`). Add `Identity` (for example `Global` or `Tag:Executives`) for one instance.
* `TenantFilter` only: reads every type in the catalogue, one call each, and reports errors per type. Use `Category` to narrow it.
* `AsApp=true` to use an application token instead of a delegated one.
