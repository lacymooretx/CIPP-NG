# Windows 365 — Cloud PCs

Lists the Windows 365 Cloud PCs in the selected tenant: who each one belongs to, its SKU, status,
provisioning policy, disk encryption state and grace period.

## Requirements

The Cloud PC API is **application-only** — it cannot be read with a delegated token. CIPP's SAM app
needs `CloudPC.ReadWrite.All` granted in the tenant (Tenants → Refresh CPV Permissions).

## "This tenant has no Windows 365 licence"

If the tenant owns no Windows 365 SKU, this page shows that message rather than an empty table.
That distinction is worth making: Microsoft returns the *same* "Access is denied" error for an
unlicensed tenant as for a genuine permission fault — even for the static image catalogue — so an
empty table would send you off repairing consent that is already correct.

If you see the licence message, **nothing needs repairing**. Buy the licence.

If the tenant *is* licensed and you still get a permission error, the message says so explicitly and
names the two fixable causes: the role not granted, or CIPP holding a cached Graph token that
predates the grant.

## Actions

Row actions cover the Cloud PC lifecycle. Three of them destroy data:

| Action | Effect |
|---|---|
| **Reprovision** | Rebuilds from the policy image. **The local disk is wiped.** |
| **End Grace Period** | **Deprovisions** the Cloud PC — a deletion, not a pause. |
| **Restore from Snapshot** | Rolls back; everything written since the snapshot is lost. |
| **Resize** | Different SKU. Data retained, but the machine restarts. |
| **Troubleshoot** | Runs Microsoft's health checks. Changes nothing. |

The three destructive actions require you to type the Cloud PC's **exact display name**. CIPP
compares it against the name it fetches from Microsoft at that moment, not against the table row,
which may be stale. There is no bulk reprovision — one Cloud PC per action, deliberately.

Snapshot IDs come from the Intune portal; CIPP does not enumerate snapshots.

These run asynchronously. Re-read the Cloud PC to watch its status change — an immediate read tells
you nothing.
