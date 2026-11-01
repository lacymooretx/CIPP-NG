# Device Control: removable storage, audit first (Vikunja CIPP-26)

Two Graph bodies that build an **audit-only** Defender for Endpoint Device Control policy. Nothing here blocks a
device. Nothing has been deployed: these are files for the operator.

| File | What it is | Graph endpoint |
|---|---|---|
| `01-removable-storage-group.reusablePolicySetting.json` | Reusable setting (Device Control "removable storage group") matching every removable media device: `PrimaryId = RemovableMediaDevices`, match any. | `POST /beta/deviceManagement/reusablePolicySettings` |
| `02-device-control-removable-storage-audit.configurationPolicy.json` | Endpoint security > Attack surface reduction > **Device Control** policy (template `0f2034c6-3cd6-4ee1-bd37-f3c0693e9548_1`): Device Control **enabled**, default enforcement **Allow**, one rule on the group above with entry type **AuditAllowed** + **Send event** for read, write, execute, file read, file write and file execute. | `POST /beta/deviceManagement/configurationPolicies` |

Setting ids, option ids and template reference ids were read from Graph in aspendora.com on 2026-10-31
(`configurationPolicyTemplates('0f2034c6-…_1')/settingTemplates`, `configurationSettings`, `reusableSettings`).
The bodies themselves have **not** been posted, so treat the first deploy as the validation.

## Why two objects

Device Control rules point at removable storage groups, and Intune stores those groups as **reusable settings**
with tenant-specific ids. The rule's "Included devices" value
(`…_ruledata_includedidlist_groupid`) is a `deviceManagementConfigurationReferenceSettingValue` holding that id,
so the policy cannot be posted until the group exists. `REUSABLE_SETTING_ID` in file 02 is the placeholder.

**CIPP gotcha:** `AddIntuneTemplate` with pasted `RawJSON` stores `ReusableSettings = @()`, so a template saved
that way deploys a policy whose rule points at a group id that does not exist in the target tenant. Capture the
template from a live policy instead (step 4 below): that path runs `Get-CIPPReusableSettingsFromPolicy`, saves the
group as an `IntuneReusableSettingTemplate` and links it, and every later deploy recreates the group first
(`Sync-CIPPReusablePolicySettings`).

## Rollout (operator)

1. **Aspendora first.** `POST /beta/deviceManagement/reusablePolicySettings` with file 01 (CIPP ExecGraphRequest,
   `Method: POST`, `AsApp: true`). Note the returned `id` and read it back.
2. Replace `REUSABLE_SETTING_ID` in file 02 with that id and `POST /beta/deviceManagement/configurationPolicies`.
   Read the policy back (`/configurationPolicies/{id}/settings`) and open it in Intune to confirm the rule shows
   the group and "Audit allowed".
3. Assign it to a pilot device group (LACY-W365, BRYAN-PC, LACY-DELL are the ASR block pilot already). After a
   check-in, `ListDefenderHardening` for aspendora.com should show **DeviceControl = Audit**. On the device,
   plug in a USB stick and confirm events (Defender `RemovableStoragePolicyTriggered` in hunting where available;
   otherwise the ControlR follow-up below).
4. In CIPP: Endpoint > MEM > Templates > add template **from the existing policy** in aspendora.com. Check the
   saved template lists one reusable setting.
5. Deploy the template to client tenants **unassigned**, or assigned to a pilot group per tenant. Never assign
   to All Devices at ring 0 without a week of pilot data.

## Ring plan to default deny

| Ring | Scope | Policy state | Exit criteria |
|---|---|---|---|
| 0 Audit | Pilot group per tenant, then All Devices | This template: default Allow, AuditAllowed on all removable media | 2 weeks of events reviewed; list of devices and USB serials/vendors actually in use |
| 1 Approved list | Same | Add a second group "Approved removable media" (descriptor `SerialNumberId` per approved device, or `VID_PID` / `VID` for an approved vendor family such as company-issued encrypted drives) with an **Allow** rule, and an **AuditDenied** + Show notification rule on "all removable media". Still default Allow. | The AuditDenied events contain only devices the business agrees should be blocked |
| 2 Deny writes | Pilot, then all | Change the "all removable media" rule to **Deny** for Write and File write (keep Read) and the approved group to Allow all. | No helpdesk tickets for a week in pilot |
| 3 Default deny | Pilot, then all | Default enforcement **Deny**, approved group Allow, everything else denied. Exceptions are added to the approved group, never by turning the policy off. | Steady state; exceptions go through a ticket with the serial number |

Exceptions are by **serial number** for one device and by **VID_PID** for a model. Avoid vendor-only (`VID`)
exceptions except for a company-issued encrypted model line: a VID covers every product from that vendor.

`ListDefenderHardening` reports DeviceControl as `Audit` (ring 0-1, Info), `Enforced` (any Deny entry or default
deny, Pass), `EnabledNoRules`, `Disabled` or `NotConfigured` (Fail).

## Licence

Device Control needs Defender for Endpoint Plan 1 or Defender for Business (included in Business Premium).
The rule settings need Windows 10.0.18362 (1903) or later (their `minimumSupportedVersion` in Graph); keep the
Defender platform current.
