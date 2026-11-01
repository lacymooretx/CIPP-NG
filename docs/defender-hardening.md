# Defender hardening pack (Vikunja CIPP-26) and MDO pending remediations (CIPP-31)

Aspendora fork additions. Everything here is **report only**: no endpoint, alert or template changes tenant
configuration by itself. Times are US Central.

## What is reachable by API and what is portal-only

Probed read-only against aspendora.com and 3endt.com on 2026-10-31 (CIPP ListGraphRequest / ExecExoRequest Get-*).

| Item | Reachable? | Evidence |
|---|---|---|
| ASR rule modes in Intune | **Yes**, Graph `configurationPolicies?$expand=assignments,settings` | aspendora "ASR Default rules" (template `e8c053d6-…_1`): 16 `_block`, 3 `_audit` (PSExec/WMI, prevalence/age, USB), per-rule exclusions as child `…_perruleexclusions`. `$expand=settings` returned all 120 of 120 settings on the largest policy. |
| ASR hit counts, advanced hunting | **No** in our tenants | `DeviceEvents`/`DeviceInfo` "Failed to resolve table or column expression" (aspendora + 3endt, 2026-07-24, `/Users/lacy/code/cipp/docs/asr-audit-reporting.md`). Code still tries it (app token) and falls back. |
| ASR hit counts, Intune report | **Not found** | No documented app-only Intune `deviceManagement/reports` export for ASR rule detections was identified; not built on. |
| ASR hit counts, endpoint event log | **Yes, via ControlR** | Event IDs 1121/1122, `Get-AsrEvents` collector already runs daily on 254 devices. CIPP now accepts its output (ExecAsrEvidence). |
| Network Protection mode | **Yes**, Settings Catalog `device_vendor_msft_policy_config_defender_enablenetworkprotection` | aspendora "Defender" (Antivirus template): `_1` = enabled (block). `_2` = audit, `_0` = disabled. |
| Device Control | **Yes** for reading/creating policies | Template `0f2034c6-3cd6-4ee1-bd37-f3c0693e9548_1`; groups are reusable settings (`reusableSettings` definitions `…_policygroups_{groupid}_groupdata_*`). Neither tenant has a Device Control policy or reusable settings today. |
| Web content filtering policies | **Portal only** | Defender portal Settings > Endpoints > Web content filtering. No Graph or MDE API documents them. |
| Advanced features toggle (enables WCF) | **Portal only** | Defender portal Settings > Endpoints > Advanced features. No documented API. |
| MDO automation "soft delete similar files / URLs" | **Portal only** | Defender portal Settings > Email & collaboration > MDO automation settings. `Get-AtpPolicyForO365` (EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen) and `Get-ReportSubmissionPolicy` (only `NotificationsFor*AirInvestigationsEnabled`) do not carry it; `Get-ATPProtectionPolicyRule` returned nothing in 3endt. EXO answers **403 for any unknown cmdlet** (`Get-ZzzNotARealCmdlet` → 403), so guessed cmdlet names cannot prove or disprove one exists; none is documented. **No standard was built**: there is nothing to read or set. |
| Pending Action Center remediations | **Yes**, Graph `security/alerts_v2` `investigationState` | Value `pendingApproval`. Not filterable server-side ("cannot be used in the $filter query option"), so CIPP filters unresolved alerts client-side. Evidence carries `remediationStatus`. |

Live finding from the probe (2026-10-31): **3endt.com has 2 MDO investigations pending approval since August**
(incident 602, created 2026-08-26 18:43 CDT (23:43 UTC); incident 603, 2026-08-27 12:58 CDT (17:58 UTC)), and
**aspendora.com has 1** (incident 949, 2026-10-30 09:01 CDT (14:01 UTC)). That is the symptom CIPP-31 is about.
aspendora also has ~100 unresolved MDO alerts titled "Test" in `queued` state since June (a custom alert policy):
noise worth cleaning up, not counted as pending.

## Endpoints

| Endpoint | Role | Input | Output |
|---|---|---|---|
| `ListAsrReadiness` | Endpoint.MEM.Read | `tenantFilter` (single), `WindowDays` 1-90 (14), `SkipHunting` | `{ Tenant, WindowDays, Evidence{Available, Source, CoverageDays, DevicesReporting, DevicesWithoutRules}, Summary{AsrPolicies, Assigned, ReadyForBlock, KeepAudit, AlreadyBlock, NotConfigured, FixConflict}, Rules[{RuleId, Rule, Mode, AuditHits, BlockHits, DevicesWithHits, Recommendation, Reason, Policies, UnassignedPolicies, Exclusions}], Errors, Notes }` |
| `ListDefenderHardening` | Endpoint.MEM.Read | `tenantFilter` (or AllTenants) | single: `{ Tenant, Controls[{Control, State, Status, Policies, Detail}], Errors, Notes }`; AllTenants: flat rows with `Tenant` |
| `ListDefenderPendingRemediation` | Security.Alert.Read | `tenantFilter` (or AllTenants), `Source` All/MDO/MDE, `LookbackDays` (90, max 180), `MinAgeHours` (24) | single: `{ Tenant, PendingCount, OverThresholdCount, MinAgeHours, Alerts[{AlertId, IncidentId, Title, ServiceSource, Status, Severity, CreatedUtc, Created (Central), AgeHours, OverThreshold, PendingActions, IncidentUrl}], AutomationSetting{State: NotApiReachable, Status: Manual, Detail}, Notes }`; AllTenants: `{ Tenant, PendingCount, OverThresholdCount, Oldest, OldestTitle, Error }` |
| `ExecAsrEvidence` | Endpoint.MEM.ReadWrite | POST `{ tenantFilter, Reports: [Get-AsrEvents JSON, ...] }` (or `Report`), max 500 | `{ Results, Stored, Rejected[] }`. Writes CIPP table `AsrEvidence` only. |

Rules of the readiness logic:

- Effective mode is tenant level over **assigned** Settings Catalog / endpoint security policies; exclusion-only and
  unassigned policies are ignored (listed in `UnassignedPolicies`). Two assigned policies with different modes =
  `Conflict`. Legacy endpoint security intents are listed in Notes, not parsed. For one device use
  ListIntuneEffectivePolicy (CIPP-19).
- `ReadyForBlock` only when the rule is in Audit/Warn **and** an evidence source covers the whole window with at
  least one reporting device **and** the rule had zero audit/warn hits. No evidence is never read as no hits.
- Evidence: advanced hunting first (`DeviceEvents` ActionType `Asr*`, stems mapped in Get-CIPPAsrRuleCatalog,
  best effort); else table `AsrEvidence` (one row per device per UTC day: per-rule Audited/Blocked/Warned counts,
  up to 5 process leaf names per rule, RulesOnDevice). Command lines, paths and user names are discarded on ingest.

## Alerts

| Alert | Interval | Raises | Lifecycle Id |
|---|---|---|---|
| `DefenderPendingRemediation` | 4h | Each alert pending approval ≥ `PendingRemediationHours` (24), measured from alert creation (Graph has no "pending since") | `PendingApproval|<alert id>`, resolves when approved/rejected/resolved |
| `AsrReadiness` | 30d | Rules ready for Block (Info), conflicting rules (Warning), one `NoEvidence` row when Audit rules have no evidence | `Ready|<rule>`, `Conflict|<rule>`, `NoEvidence`. Turn on re-notify to repeat monthly. |

Both skip reporting (no reconcile) when their reads fail, so "could not check" never resolves open items.

## Rollout (operator)

1. Merge `feat/cipp26-31-defender`; run `build/tools/build-openapi.ps1` (openapi.json not hand-edited) and the
   Pester tests below.
2. Deploy CIPP-NG as usual (stop/start to pull the image, check `/version.json`).
3. Read-only smoke: `ListDefenderPendingRemediation?tenantFilter=3endt.com` should list incidents 602 and 603;
   `ListDefenderHardening?tenantFilter=AllTenants`; `ListAsrReadiness?tenantFilter=aspendora.com` (expect
   KeepAudit with "no ASR evidence" until step 4).
4. ControlR follow-up (below) to feed `ExecAsrEvidence`; after 14 days of data `ListAsrReadiness` can say
   ReadyForBlock.
5. Schedule alerts: `DefenderPendingRemediation` (4h) on all tenants; `AsrReadiness` (30d) on Intune tenants.
6. Device Control: see `docs/defender-templates/README.md` (aspendora pilot first, capture template from the live
   policy, then roll out unassigned).
7. By hand per tenant (portal-only): MDO automation settings → soft delete for similar files and similar URLs;
   Advanced features → Web content filtering on, then a WCF policy. Record the state in Hudu per tenant.
8. Clear the existing pending approvals (3endt 602/603, aspendora 949) in Action Center.

## Follow-ups outside CIPP

- **ControlR / n8n:** after the daily `Get-AsrEvents` run, POST each device's JSON to CIPP `ExecAsrEvidence`
  (`{ tenantFilter: <M365 default domain>, Reports: [...] }`) with a CIPP API client that has
  Endpoint.MEM.ReadWrite. Easiest in n8n workflow `NKvMVNmYZqQellh2`, which already parses every device's run.
  ControlR tenants that are not CIPP tenants (Digital Systems, Michael Carroll, Oakland Development, Assessment
  Holding) have no Intune ASR policy, so readiness does not apply there.
- **ControlR:** a Device Control event collector (Defender Operational log / `RemovableStoragePolicyTriggered`)
  so ring 0 audit data is visible without advanced hunting; same ingest pattern if wanted.
- **AsrEvidence retention:** rows are never pruned (≈250 devices × 365 rows/year). Add a monthly cleanup of rows
  older than 90 days if it matters.
- **Frontend pages** for the three List endpoints were not built (API/MCP only). Adding nav entries needs docs
  pages (tests/utils/help-links.test.js).

## Tests

`backend/Tests/Security/DefenderHardening.Tests.ps1` (pure rules: catalog, settings parser incl. the shipped
template, assignment state, mode resolution, recommendations, evidence row + summary, hardening state, pending
alert selection), `backend/Tests/Alerts/Get-CIPPAlertDefenderPendingRemediation.Tests.ps1`,
`backend/Tests/Alerts/Get-CIPPAlertAsrReadiness.Tests.ps1`. Written without being run (pwsh not available in the
authoring sandbox).

## Licence notes

- ASR, Network Protection, Device Control: Defender for Endpoint P1 / Defender for Business (Business Premium).
- Web content filtering: MDE P1/P2 or Defender for Business.
- Advanced hunting device tables: MDE P2 covering the devices (not Defender for Business); see asr-audit-reporting.
- AIR for email and the MDO automation settings: Defender for Office 365 **Plan 2** (or E5 / Defender Suite).
  Tenants on MDO P1 (Business Premium) do not run AIR, so they will show no pending approvals; that is not a
  pass for the soft-delete setting.
