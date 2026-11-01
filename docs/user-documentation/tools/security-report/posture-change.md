# Security Posture Change

A client-facing, month-over-month view of the tenant's security posture. It uses data CIPP already collects, with no extra Graph calls:

* the stored **CIPP test results** (ZTNA, CIS, EIDSCA, ORCA, CISA, Essential Eight, Azure, custom tests, ...) written by the nightly test run;
* the cached **Microsoft Secure Score** (the same nightly cache as the Secure Score report).

Run it from **Tools > Reports**, report type **Security Posture Change** (`ReportType` `PostureChange`).

## How the history is built

Each run stores a compact **snapshot** of the tenant's posture: for every check its id, title, suite, category, status and risk, plus the Secure Score. Snapshots live in the `CippPostureSnapshots` table, one per tenant per day (US Central date); a second run on the same day replaces that day's snapshot. Snapshots older than about 400 days are pruned.

A snapshot is stored when:

* the **Security Posture Change report runs** (on demand or scheduled), and
* the **PostureSnapshot scripted alert** runs. Add it under the tenant alert configuration with the recommended interval of 30 days. It never sends an alert; it only records the snapshot, so a tenant whose report is only run on demand still builds a monthly history.

A snapshot is **not** stored when the tenant has no CIPP test results yet, so a tenant that has not been tested never becomes an empty baseline.

The first time the report runs for a tenant there is nothing to compare with. The report says **"Baseline taken today; changes appear from next month."** and lists the current open issues by priority.

## What it compares with

The current posture is compared with the **newest snapshot at least 25 days old**. If every earlier snapshot is younger than that, the oldest one is used and the report notes the shorter window.

## Sections

| Section | Contents |
| ------- | -------- |
| Since Last Review | Secure Score then and now (percentage and points), open issues then and now, fixed and new counts. |
| Fixed Since Last Review | Checks that were failing or needed review last time and pass now. |
| New Issues | Checks open now but not last time. **Was passing**: a regression. **Newly assessed**: the check was skipped or not licensed last time. **New check**: the check did not exist last time. |
| Still Open: Do Today | Every open check (new or carried over) with Critical or High risk. |
| Still Open: This Month | Open checks with Medium risk. |
| Still Open: Long-term | Open checks with Low or no risk rating. |
| No Longer Assessed | Checks that were open last time but are now skipped, unlicensed or no longer reported. They are **not** counted as fixed. Shown only when there are any. |

## Rules

* **Open** means Failed (including Active and Postponed) or Investigate. **Not assessed** means Skipped, Informational or Unlicensed: these say nothing about configuration, so moving to or from them is never counted as a fix or a regression.
* Checks are matched by test id. If a check's id changed between runs, it is matched by its title instead, but only when exactly one old check has that title.
* Secure Score is compared as a **percentage** in the narrative, because Microsoft raises the maximum score as it adds controls; the points change is shown alongside.
* The report only reads stored data. How current it is depends on the nightly test run and Secure Score cache.

## API

`GET /api/ListPostureChange?tenantFilter=<domain>&minDays=25` returns the same comparison as JSON. It is read only and never stores a snapshot.
