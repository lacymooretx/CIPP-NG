# Vendor Access

Lists every outside party with standing access to your client tenants, in one table. Aspendora fork addition. That covers four kinds of access:

| Type | What it is |
| --- | --- |
| App | An enterprise app (service principal) owned by another organisation. Apps owned by the tenant itself, Microsoft apps and managed identities are left out. |
| Outside admin (GDAP/DAP) | A group or account from another organisation that holds directory roles in the tenant. This is how another partner's GDAP or DAP access shows up. Aspendora's own CIPP partner tenant is listed as one Low-risk row, but is not counted in the totals. |
| Guest admin | A guest account that holds directory roles. |
| Service provider | Another organisation set as a service provider in the tenant's cross-tenant access settings. |

Open it from **Tenant > Reports > Vendor Access**. It works for one tenant or for **All Tenants**.

## Where the data comes from

The page reads a saved snapshot, not live data. The snapshot is rebuilt for all tenants every Monday before the weekly email, and when you press **Rebuild now**. A tenant that has no snapshot yet is built when you open the page. Rebuilding across all tenants takes a minute or two. The time of the snapshot is shown above the table, in US Central.

* Apps and their permissions come from the CIPP reporting database. App risk comes from CIPP's risky-permissions catalogue (the same rating as [App Permission Exposure](app-permission-exposure.md)).
* Role assignments and cross-tenant service providers are read live from Graph when the snapshot is built.
* App and guest sign-ins come from Entra ID P1 sign-in data. A tenant without P1 shows **Unknown** for sign-in and is listed in a notice at the top of the page.

Tenants that could not be fully read are listed in a warning at the top of the page, with the error. A tenant whose rebuild fails keeps its previous snapshot.

## Risk

| Type | Risk |
| --- | --- |
| App | The rating from the risky-permissions catalogue. An app that holds no catalogued permission is Low, but its permissions are still listed in **Access**. |
| Outside admin | Critical if it includes Global Administrator, High if it includes other privileged roles, otherwise Medium. |
| Guest admin | High if it holds privileged roles, otherwise Medium. |
| Service provider | Medium. Aspendora's CIPP partner tenant is Low. |

The row details list the reasons for each rating.

## Columns

* **Type**, **Who**, **Organisation**, **Organisation type** and **Vendor**: who holds the access. With All Tenants selected, the tenant is shown too.
* **Access**: the permissions or directory roles held.
* **Sign-in activity** and **Last sign-in**: Active, Stale 45+ days, No sign-in recorded, or Unknown.
* **Stale**: Yes when the last sign-in is 45 or more days ago, or when sign-in data exists and no sign-in is recorded. Unknown when the tenant has no P1.
* **New credentials**: for apps, unexpired sign-in credentials added in the last 30 days.
* **New this week**: first seen in the last 7 days. On a tenant's first build every row is a baseline and none is marked new.
* **Removed**: gone since the last build. Removed rows stay visible for 7 days and are purged after 30.
* **First seen** and **Enabled**.

Preset filters: Critical risk, High risk, New this week, Stale, Outside admins (other partners), Guest admins, Apps and Removed this week.

## Actions

| Action | What it does |
| --- | --- |
| View app in CIPP | Opens the enterprise app page for an app row. |
| Disable app (vendor kill switch) | Sets the app's service principal to disabled in that tenant, after a confirmation. It stops signing in and getting tokens at once. Its permissions stay in place. |
| Enable app | Turns a disabled app back on. |
| Email it now | Sends the weekly email now, from the saved snapshot. |

Outside admins cannot be removed from CIPP. The customer's Global Administrator ends the relationship in the Microsoft 365 admin center under **Settings > Partner relationships**. The row details say this, and the Vendor Access article in Hudu has the steps.

## Weekly email

The report is emailed every Monday at 07:00 US Central, for all tenants. The line above the table shows whether the email is on, its schedule, its recipient and the last send. The check runs hourly, so a missed 07:00 run is caught up later the same Monday, and each Monday is sent only once. The recipient and the on/off switch are set through `ExecVendorAccessReport` with `Action=Settings`; the page has no settings form.

## Permissions

Viewing needs `Tenant.Application.Read`. **Disable app**, **Enable app** and **Email it now** need `Tenant.Application.ReadWrite`, and are hidden without it.

## API

* `GET /api/ListVendorAccess?tenantFilter=<tenant|AllTenants>` returns `GeneratedAt`, `Summary`, `Tenants` and `Items`. Add `Refresh=true` to rebuild first.
* `POST /api/ExecVendorAccessReport` with `Action` set to `Preview` (the email HTML), `Send`, `Settings`, `GetSettings` or `Reset`. `Reset` clears the saved snapshot, but not the settings or send history, so the next build is a new baseline with nothing marked new or removed. Use it after a change to what the report lists.
