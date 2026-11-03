# What Changed

Shows what changed in one tenant, so a day when nothing happened has nothing to read. The page is read only. It uses data CIPP already holds, needs no new tenant permissions, stores nothing and sends nothing.

Open it from **Tenant > Reports > What Changed** and select a single tenant. **Window** sets how far back to look, from the last 24 hours to the last 30 days. Times are US Central with UTC alongside.

## What counts as a change

| Source | Listed | Where it comes from |
| --- | --- | --- |
| Alerts | New, reopened and resolved items in the window. Items with a hidden snooze are counted, not listed. | AlertLifecycle table |
| Test results | Tests that became new issues or were fixed since the posture snapshot. Tests still open are not listed. | Stored test results and posture snapshots |
| Secure Score | A move of 1 percentage point or more. | Nightly Secure Score cache |
| Message Center | Action-required, retirement and security posts that are new or updated, and any post whose deadline reaches 30, 7 or 0 days left. | Nightly Message Center cache |

The new-or-updated Message Center window is one day longer than the window you pick. The cache is nightly, so without that a post published just after a sync could be missed, and it can show on two days instead.

**Sources and data age** at the bottom gives each source's detail, including open alert items not seen for over 7 days and cache types older than 3 days. Those are not changes, so they stay out of the main list.

## How to read the page

Each source is read separately:

* **Could not read:** the read failed or there was nothing stored. The page shows a warning and its counts show "Could not read". It is never shown as no changes.
* **Nothing to compare with:** read, but with no usable earlier data, or no tracked alerts at all for this tenant.
* **Read, but old data:** the test run or cache is more than 3 days old.

"Nothing changed" appears only when every change source was read cleanly. Otherwise the line names only the sources that were read cleanly.

## Test results and snapshots

Test results have no date of their own, so a change can only be placed after the last posture snapshot. Snapshots are monthly by default, from the PostureSnapshot alert or when the Security Posture Change report runs. When the newest usable snapshot is older than the window, the source shows as **Nothing to compare with**, and the differences sit in a closed section labelled with the snapshot date.

Daily test changes need a daily snapshot. To get that, schedule the PostureSnapshot alert daily for the tenant. It sends no alert. Snapshots are kept for 400 days, so check the table growth before doing this across every tenant.

## Permissions

The page needs `Tenant.Reports.Read`. That includes the alert and Message Center rows on the page, which elsewhere need `CIPP.Alert.Read` and `Tenant.Administration.Read`. If a custom role has reports access and should not see alert items, block `ListTenantChanges` on that role. Alert rows carry only the alert name, its short preview, its status and its dates, but the preview can name a user.

## API

`GET /api/ListTenantChanges?tenantFilter=contoso.onmicrosoft.com&days=1` returns the record: `Verdict`, `Summary`, `Sources`, `Changes` and `OlderTestChanges`. The status is 200 when every source was read, 207 when some failed and 500 when all failed, each with the same body. `AllTenants` returns 400, and an unknown tenant 404.
