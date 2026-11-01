# Audit-log detections: lateral sharing phishing (CIPP-13) and email-security tampering (CIPP-32)

Aspendora fork addition, 2026-10-31. Both detections only alert. Neither one changes tenant configuration.

## CIPP-13: SharingBurst scripted alert

**What it detects**

- **UserBurst:** one account shares with 25 or more distinct external recipients inside any 60-minute window. It's a sliding window, so a burst that crosses an hour boundary still counts.
- **FileSpread:** one item reaches 25 or more distinct external recipients across the 24-hour lookback, even when the shares are spaced out.
- **LinkMailBlast:** an account creates anyone/company/secure links, then sends mail to 25 or more new external recipients in 24 hours. The recipient count must also be at least 3x the account's own daily average over the previous 7 days.

**What each finding includes**

- Any risky or new-country successful sign-in in the 24 hours before the sharing started.
- The send-spread comparison.
- Ready parameters for the existing actions:
  - `ExecRemoveSharingLink`: taken from the sharing-links cache, or resolved live with `ListSharingBurst?resolve=true`.
  - `ExecBulkRemoveSharingLinks` per site, with `Scope=External`.
  - `ExecSetOneDriveSharing` with `SharingCapability=Disabled`.

**Severity:** High when any of these is true. Otherwise Medium.

- The file is a lure type (OneNote, PDF, HTML, SVG, URL, EML).
- A notable sign-in came first.
- Sent mail spiked.
- The finding is LinkMailBlast.
- Recipients reached twice the threshold.

**Files**

- `Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertSharingBurst.ps1`
- `Modules/CIPPCore/Public/SharingLinks/{Get-CIPPSharingBurstReport,Get-CIPPSharingBurstFindings,ConvertTo-CIPPSharingEvent,Measure-CIPPSendSpread,Get-CIPPSharingBurstSignInContext}.ps1`
- Report endpoint `ListSharingBurst`, role `Sharepoint.Site.Read`.
- The BEC hook: `Push-BECRun` adds `SharingBursts`, and `Get-CIPPBecScore` adds the `MassSharing` signal (weight 4, `BecHeuristics.json`, `sharingBurst` thresholds).

### Why Search-UnifiedAuditLog and not the two suggested options

| Option | Why not |
|---|---|
| (a) Graph `security/auditLog/queries` | Asynchronous. Every run POSTs a search object into the tenant's Purview. That needs a two-phase run (create now, read next run), plus AuditLogsQuery.Read.All consent. It also competes with the Webhookv2 pipeline for the tenant's roughly 10 concurrent audit queries; Push-AuditLogSearchCreationV2 already handles 429s from that cap. |
| (b) The Webhookv2 stream (`Test-CIPPAuditLogRules`) | It ingests only `exchangeAdmin` and the AAD record types (`New-CippAuditLogSearchV2`). SharePoint sharing would have to join every tenant's 35-minute searches. The rules engine matches one record at a time, so "25 distinct recipients in an hour" or "one file over a day" would need a new stateful aggregation table that spans windows. |
| **Chosen:** `Search-CIPPBecAuditLog` (Search-UnifiedAuditLog through New-ExoRequest) | Synchronous, paged, time-bisected, and it reports completeness. The BEC check already runs it in production, so it needs no new permission and creates no tenant objects. Message trace (`Get-CIPPBecMessageTrace`) supplies the send-spread data. |

IP is ignored for detection on purpose. These events come from Microsoft data-centre addresses.

### Schedule (not created; Lacy to create)

ScheduledTask in the same shape as the live CompromiseSweep task:

- Command: `Get-CIPPAlertSharingBurst`
- Tenant group: Managed Clients (`76e328cc-5669-4273-8830-c653ac289358`)
- Recurrence: `1h`
- PostExecution: `Email,PSA`
- Parameters: `{"InputValue":{"SharingBurstLookbackHours":"24","SharingBurstRecipients":"25","SharingBurstWindowMinutes":"60","SharingBurstFileRecipients":"25","SharingBurstSendSpread":"25","SharingBurstAllowList":"","SharingBurstMaxPerCycle":"10"}}`
- Suggested subject: `SECURITY: possible lateral phishing (mass external sharing)`

## CIPP-32: email security, TABL and transport rule changes

**Engine changes**

- `Test-CIPPAuditLogRules` stamps three fields on every record:
  - `CIPPActorClass`: MSP, CIPP, Microsoft, OtherPartner, App or Tenant. Computed by `Get-CIPPAuditActorClass`.
  - `CIPPActorIsMSP`: `True` or `False`.
  - `CIPPActorDetail`.
- How the classifier decides:
  - **MSP:** a GDAP admin of the MSP partner tenant. In Exchange this shows as `<customer>.onmicrosoft.com\tenant: <partner tenant id>, object: <partner user id>`. In Entra it shows as an `ActorContextId` that isn't the customer's tenant. CIPP's own delegated calls are MSP too.
  - **CIPP:** CIPP acting app-only.
  - **Microsoft:** NT SERVICE / NT AUTHORITY actors, or UserType 3 or 4.
- MSP tenant ids are `$env:TenantID` plus the optional `CIPP_MSP_TENANT_IDS` app setting (comma separated). If neither is set, any partner counts as the MSP.
- To exclude the MSP, a rule adds `CIPPActorIsMSP eq False`. A rule can also skip the condition or tighten it, for example with `CIPPActorClass ne OtherPartner`.
- `New-CIPPAlertTemplate` builds the body for these cmdlets with `Get-CIPPEmailSecurityChangeContext`. The body has:
  - the actor and its class, the IP, the cmdlet and target, and every parameter (new values);
  - "before" values from the CIPP DB cache snapshot, when the object is cached;
  - one `drift: <standard label> (standards.<name>, template '<name>')` line per applied standard that manages that object type. Nothing is reverted.
  - This also improves the existing New-TransportRule rule.
- Three presets in `AuditLogTemplates.json`: `EmailSecurityPolicyChanged`, `TenantAllowBlockListChanged`, `TransportRuleChanged`.

### Rule definitions (not created; Lacy to create via AddAlert)

All three rules share these fields:

```json
"tenantFilter": [{"label":"Managed Clients","value":"76e328cc-5669-4273-8830-c653ac289358","type":"Group"}],
"excludedTenants": [],
"actions": [{"value":"generatemail","label":"Send Email"},{"value":"generatePSA","label":"Create ticket in PSA"}],
"becActions": [],
"logbook": {"value":"Audit.Exchange","label":"Exchange"},
"PsaTicketPriority": ""
```

Each rule's conditions: the Operation list below, plus these two conditions.

```json
{"Property":{"value":"String","label":"CIPPActorIsMSP"},"Operator":{"value":"eq","label":"Equals to"},"Input":{"value":"False"}},
{"Property":{"value":"String","label":"CIPPActorClass"},"Operator":{"value":"ne","label":"Not Equals to"},"Input":{"value":"Microsoft"}}
```

1. **Email security policy changed.** CustomSubject `SECURITY: %Operation% in %tenant% by %username%`. The Operation `in` list is exactly the 56 cmdlets in the `EmailSecurityPolicyChanged` preset:
   - New/Set/Remove of: AntiPhishPolicy, HostedContentFilterPolicy, HostedOutboundSpamFilterPolicy, MalwareFilterPolicy, SafeAttachmentPolicy, SafeLinksPolicy.
   - Set-HostedConnectionFilterPolicy and Set-AtpPolicyForO365.
   - New/Set/Remove/Enable/Disable of: AntiPhishRule, HostedContentFilterRule, HostedOutboundSpamFilterRule, MalwareFilterRule, SafeAttachmentRule, SafeLinksRule.
   - Set/Enable/Disable of ATPProtectionPolicyRule and EOPProtectionPolicyRule.
2. **Tenant Allow/Block List changed.** New/Set/Remove of TenantAllowBlockListItems and TenantAllowBlockListSpoofItems.
3. **Transport rule changed.** Set-TransportRule, Remove-TransportRule, Disable-TransportRule, Enable-TransportRule. New-TransportRule stays in the live rule b17f3e83.

Write the Operation condition the way the live rules store it:

```json
{"Property":{"value":"List:Operation","label":"Operation"},"Operator":{"value":"in","label":"In"},"Input":{"value":["Set-TransportRule","Remove-TransportRule","Disable-TransportRule","Enable-TransportRule"]}}
```

## Testing

- **CIPP-32:** `backend/Tests/Webhooks/Get-CIPPAuditActorClass.Tests.ps1` and `Get-CIPPEmailSecurityChangeContext.Tests.ps1`. The preset samples (`Fixtures/AuditLogPresetSamples.json`, `derived-*` samples) run through `AuditLogPresets.Samples.Tests.ps1`.
- **CIPP-13:** `backend/Tests/Private/Get-CIPPSharingBurstFindings.Tests.ps1`, `backend/Tests/Alerts/Get-CIPPAlertSharingBurst.Tests.ps1`, and the MassSharing case in `Get-CIPPBecScore.Tests.ps1`.
- **Live check after deploy (read only):**
  - Call `ListSharingBurst?tenantFilter=3endt.com&hours=72&recipients=5` and confirm the findings and ReadyActions.
  - For CIPP-32, check `CIPPActorClass` on the next stored audit alert (ListAuditLogs → RawData).

## Risks

- **Audit lag:** SharePoint events usually land within 30-90 minutes, but sometimes take up to 24 hours. Exchange admin events can take hours to start flowing on a new tenant. The 24-hour overlapping lookback and stable Ids absorb this.
- **Licence:**
  - Unified audit must be on.
  - Sign-in correlation needs Entra ID P1, and risk detail needs P2. Without them the alert says "not checked".
  - Message trace has a 10-day limit.
- **Unverified:** TABL cmdlets were not checked in a real record. If they log only under the `tenantAllowBlockList` record type rather than `exchangeAdmin`, the Webhookv2 stream won't see them. Verify with `Search-UnifiedAuditLog -Operations New-TenantAllowBlockListItems` on a tenant, after making a deliberate test change.
- **ExecRemoveSharingLink ids:**
  - The cache only covers links found by the last sharing sync, so new links need `resolve=true`.
  - ExecBulkRemoveSharingLinks is cache-based and site-wide. Review before running it.

## Rollback

- Disable or delete the three rules and the scheduled task.
- The code paths stay inert without them. The actor fields are extra properties, and the alert body change only affects these cmdlets.
