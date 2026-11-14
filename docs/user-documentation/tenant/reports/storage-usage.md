# M365 Storage & Usage

Shows how much Microsoft 365 storage one tenant uses and how fast it is growing, across Exchange, OneDrive and SharePoint. Aspendora fork addition. The page is read only.

Open it from **Tenant > Reports > M365 Storage & Usage** and select a single tenant. All Tenants is not supported: storage history is stored per tenant, and a total across clients with unrelated quotas means nothing.

## Who it covers

Managed clients only. Membership syncs from ConnectWise. For any other tenant the page says which status the tenant has and shows no data.

## Where the data comes from

The page reads the daily history stored in the `CippStorageTrend` table: one row per tenant per day with mailbox, OneDrive and SharePoint bytes. The history is written by the storage collection (`Push-CIPPStorageSnapshot`), not by this page. The first collection backfills up to 180 days from Microsoft's storage reports. Until a tenant has been collected, the page says that no history is stored yet.

Sizes use binary units (1 GB = 1024³ bytes), the same as Microsoft and the emailed report.

## Tiles

| Tile | Shows |
| --- | --- |
| Total consumption | The latest total, and the date it is from. |
| Growth rate | Bytes per day, from the last 90 days when there is that much history (otherwise 30, 180 or all of it). Confidence is High with 90 or more days of history, Medium with 14 or more, otherwise Low. |
| Trend | Accelerating, Growing, Flat or Shrinking, and how many one-off changes were left out of the rate. |
| History held | How many days are stored, and the date range. |

**Accelerating** means the last 30 days are growing more than twice as fast as the last 90, and at least 250 MB a day faster. **Shrinking** means both the basis rate and the 30-day rate are zero or less.

## Chart and growth windows

The chart stacks Exchange, OneDrive and SharePoint over time. Days Microsoft did not report are carried forward from the previous value rather than drawn as zero.

**Growth by window** shows the rate and the total change for the last 30, 90 and 180 days, where there is enough history for each. A single cleanup or migration can make one window disagree with the others, so all three are shown.

A one-day change of 5% of the tenant's current size or more (at least 100 MB) counts as a one-off change. It is left out of the per-day rates but kept in each window's total change, and a note says how many were found.

## More detail

Per-mailbox and per-site detail, quota risk and archival candidates are in the **M365 Storage & Usage Report** under **Tools > Reports**, which can also be emailed on a schedule.

## Permissions

The page needs `Tenant.Reports.Read`.

## API

`GET /api/ListStorageTrend?TenantFilter=<tenant>` returns `Tenant`, `ManagementStatus`, `Collected`, `Days`, `Series`, `Latest`, `Growth` and `Message`. Add `Days=<n>` to return only the most recent days. `AllTenants` returns 400. An unmanaged tenant returns 200 with `Collected = false`.
