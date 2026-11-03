# Conditional Access plans and break-glass exclusion monitoring

Aspendora fork, Vikunja CIPP-56 (items 2-5) and CIPP-54 (Phase 1). Added 2026-11-03. Report only: nothing here writes to a tenant, and there is no plan write support.

## Why

Rules in a Conditional Access plan do not appear under `identity/conditionalAccess/policies`, on beta or v1.0 (tested live 2026-11-03). Plans exist only on beta. Until now CIPP reported a clean result even when a plan rule could catch a break-glass account.

Directory audit keeps 30 days, which is how the cause of 3E's lost exclusion was lost. The new alert records the actor when the change happens.

## What changed

| Piece | Where | Behaviour |
|---|---|---|
| Plan read | `Get-CIPPConditionalAccessPlans` | Beta only, delegated then app-only, one rules call per plan. Throws if the list cannot be read. |
| Cache | `Set-CIPPDBCacheConditionalAccessPlans`, type `ConditionalAccessPlans`, in the `ConditionalAccess` collection | One more read per tenant per collection run. A failed read keeps the old rows. |
| Warning | `Get-CIPPCAPlanSummary`, `Get-CIPPCAPlanWarning`, `ListConditionalAccessPlans` | "This tenant has N plans and M rules that CIPP does not evaluate." Shown on the posture, gap analysis, drift and CA list pages. The CA list shows it for a single tenant, not AllTenants. |
| Plan alert | `Get-CIPPAlertConditionalAccessPlans` (suggested 1d) | One row per plan, keyed on plan id. Notifies once, resolves when the plan is deleted. A failed read does not report. |
| Posture | `Test-CIPPBreakGlassPosture` | `Plans\|present` is Error. If the beta read fails, `PlansUnknown` is Info and the report is not blocked. |
| Exclusion alert | `Get-CIPPAlertBreakGlassExclusionChange` (suggested 30m) | High, naming the actor, when a CA policy update removes a registered account or a group holding one, or when anything but a registered account joins an exclusion group. Says whether the account is still excluded another way. |
| Group check | `Test-CIPPBreakGlassPosture` | `ExclusionGroupMember\|group\|member` is Error for each transitive member beyond the registered accounts. A failed member read goes to `Errors`, so the weekly alert skips instead of clearing. |
| RMAU check | `Test-CIPPBreakGlassPosture` | `NotRestricted\|account` is Info. For a restricted unit holding break-glass objects: `RmauAdmin` and `RmauMember` are Warning. Unrelated restricted units are ignored. |
| AU cache | `Set-CIPPDBCacheAdministrativeUnits` | Adds `isMemberManagementRestricted`. |

**Exclusion group definition.** Groups are not registered. An exclusion group is any group that holds a registered account and is excluded from at least one CA policy.

## Alert noise

Neither new alert is scheduled, and the code enables nothing. To turn one on, add it under Alerts.

Each finding notifies once through `Write-AlertTrace`:

- The plan alert uses state mode, and its row Id does not change when rules are added.
- The exclusion alert uses `-Append`, and its row Id is the audit event id, so overlapping lookbacks do not repeat.

A bulk edit of many policies gives one row per audit event.

One condition can reach two alerts, because they answer different questions. A new plan shows on the plan alert and at the next weekly posture run. An added group member shows on the exclusion alert and at the next posture run.

## Known limits

- Updates to a plan's shared conditions are not watched. Only the activity `Update conditional access policy` is. Only `Add conditional access policy plan` has been seen live, and the plan alert covers that.
- If an account's group membership cannot be read, a group removal can be missed for that run. It is logged, and the event stays in the lookback for later runs.
- Posture gains Info findings for unprotected accounts. They show on the page and never raise tickets.
- Plan rule evaluation (CIPP-56 item 6), `New-CIPPCAPolicy` adding the exclusion group, and the RMAU deploy action are not built.

## How to test

```
cd backend
pwsh -NoProfile -Command "Invoke-Pester Tests/Tenant/CAPlansBreakGlass.Tests.ps1, Tests/Alerts/Get-CIPPAlertBreakGlassExclusionChange.Tests.ps1, Tests/Tenant/BreakGlassPosture.Tests.ps1"
```

Audit fixtures follow real `directoryAudits` records from 3endt.com, read on 2026-11-03.

## Rollback

Revert the commit. The `ConditionalAccessPlans` cache rows are then unused and harmless.
