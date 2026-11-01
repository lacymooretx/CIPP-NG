# Entra Recovery Coverage

Shows, per tenant, what you could roll back to after a compromise or a bad change: Microsoft's own Entra Backup and Recovery snapshots, and CIPP's scheduled tenant backups. The page reads only. It does not schedule a backup or restore anything. Select a tenant, or **All Tenants** to see every managed tenant.

## Why both

Microsoft Entra Backup and Recovery takes one snapshot a day of users, groups, applications, service principals, Conditional Access policies, named locations, the authentication methods policy and the authorization policy. It keeps about 5 days of snapshots (the Graph documentation says 5; the Entra overview page says 7) and cannot bring back a hard-deleted object. A compromise noticed after a week therefore has no native snapshot to roll back to. A daily CIPP backup with a longer history covers that gap for Conditional Access, users and groups.

## Columns

| Column | Meaning |
| ------ | ------- |
| CIPP status | **Covered**: a scheduled CIPP backup covers the tenant, the last one is recent, and it includes Conditional Access, users and groups. **Partial**: backups run but Conditional Access or users/groups are switched off. **Gap**: no scheduled backup, the task is disabled, no backup has been taken, or the last one is older than 2 days. |
| Gaps | Every rule that applied. |
| Last backup, age | The newest CIPP backup for the tenant, from the backup history. |
| Components | What the backup task is set to include (`ca`, `users`, `groups`, `intuneconfig`, ...). |
| Last backup items | Item counts captured by the newest backup (backups written before the integrity manifest existed show nothing here). |
| Tasks | The backup task(s) that cover the tenant. A task for All Tenants or a tenant group counts for every tenant in it, minus its exclusions. |
| Entra licence | P2, P1, None or Unknown. Entra Backup and Recovery needs Entra ID P1 or P2. Microsoft 365 Business Premium includes P1. |
| Native status | **Available**, **No snapshots yet**, **No permission (EntraBackup.Read.All)**, **Not licensed**, or an error. |
| Snapshots, latest, window | How many native snapshots exist, the newest one, and how many days back the oldest reaches. |
| Soft-deleted CA policies / named locations | Deleted Conditional Access policies and named locations that can still be restored (30 days). |

## Restoring

* **Deleted users, groups, applications, service principals and administrative units**: use **Restore Deleted Object**, which opens [Deleted Items](../../identity/administration/deleted-items.md). Restoring from the recycle bin keeps the object ID, so group memberships, app assignments and Conditional Access references come back with it. This works for 30 days after deletion.
* **Deleted Conditional Access policies and named locations** are not in the directory recycle bin, so Deleted Items does not list them. Restore them in the Entra admin center under **Entra ID > Conditional Access > Deleted policies**, or with Graph (`POST identity/conditionalAccess/deletedItems/policies/{id}/restore`). This page counts them so you know they are there.
* **Rolling settings back** (a changed CA policy, a weakened authentication methods policy): use **Entra Backup and Recovery** in the Entra admin center (Backup and recovery in the left navigation) if the change is less than about 5 days old, or the CIPP backup restore wizard for Conditional Access.
* **Hard-deleted objects** cannot be recovered by either. Recreate them.

## What no backup here covers

CIPP tenant backups have no component for the authentication methods policy, app registrations, service principals, or named locations that no Conditional Access policy uses (the `ca` component saves each policy together with the named locations it references). For those, the native 5-day window is the only rollback.

{% hint style="warning" %}
**No permission** on every tenant means the CIPP app does not have the Microsoft Graph application permission `EntraBackup.Read.All`. Add it to the CIPP-SAM app permissions and run a CPV refresh so each tenant consents. Until then, check snapshots in the Entra admin center.
{% endhint %}

## Alert

The **BackupCoverage** alert (Alerts > Add alert, recommended weekly) raises one alert per tenant and gap: no scheduled backup, disabled task, no backup yet, stale backup, or Conditional Access / users and groups left out. It makes no Graph calls. Set **Backup counts as stale after X days** to change the 2-day default.

Aspendora fork addition (Vikunja CIPP-17). Endpoint: `/api/ListEntraRecoveryCoverage?tenantFilter=<tenant or AllTenants>&maxBackupAgeDays=2&skipLive=false`.
