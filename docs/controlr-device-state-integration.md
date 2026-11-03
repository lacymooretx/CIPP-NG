# Device state endpoints for ControlR

Aspendora fork addition. ControlR calls these with its existing CIPP API client. All three are read-only: GET, Graph
GET only, nothing in a tenant changes. Timestamps come from Graph in UTC.

The fourth ControlR request, a write that applies a setting to a device or group, is **not built**. It has not been approved.

| ControlR asked for | Endpoint | Role |
|---|---|---|
| Configuration profile and CSP assignment plus state, per device | `GET /api/ListDeviceConfigurationState` | `Endpoint.MEM.Read` |
| Compliance policy state, per device | `GET /api/ListDeviceComplianceState` | `Endpoint.MEM.Read` |
| Effective policy for a device | `GET /api/ListDeviceEffectivePolicy` | `Endpoint.MEM.Read` |

The API client's role must include `Endpoint.MEM.Read`.

## Request

| Parameter | Required | Meaning |
|---|---|---|
| `tenantFilter` | Yes | One tenant, by domain or id. `AllTenants` is refused. |
| `DeviceId` | One of these two | Intune `managedDeviceId` or Entra `deviceId`. Must be a GUID. Not the Entra object id. |
| `SerialNumber` | One of these two | Exact match. If both are sent, `DeviceId` wins. |
| `IncludeSettings` | No, default `false` | Configuration and compliance only. `true` returns every setting of every policy, at one paged Graph read per policy. By default only failing policies are read and only their failing settings are returned. |
| `IncludeAssignments` | No, default `true` | Configuration only. `false` skips the assignment evaluation: faster, but `Type` and `Assignment` are blank and `notReported` rows are not listed. |

## Status codes

Failure is never an empty list. An empty `Results` on a 200 with `Partial: false` means Graph really returned none.

| Status | Meaning | `Results` holds |
|---|---|---|
| 200 | Answered. Check `Partial`: when `true`, some reads failed and `Errors` says which. | The rows |
| 400 | No tenant, no device key, or a `DeviceId` that is not a GUID. | Message |
| 404 | No managed device matches. `Detail` carries Graph's text when a by-id read failed. | Message |
| 409 | The serial, or rarely the Entra id, matches several records (re-enrolment, or an OEM placeholder serial). `Candidates` lists them, newest sync first. Retry with `DeviceId` set to one `ManagedDeviceId`. | Message |
| 500 | The device lookup or state collection read failed. | `Failed: <Graph error>` |

CIPP's auth layer answers 401 or 403 before any of this runs.

## ListDeviceConfigurationState

```
GET /api/ListDeviceConfigurationState?tenantFilter=contoso.com&SerialNumber=ABC1234
```

```json
{
  "Device": {
    "ManagedDeviceId": "11111111-1111-1111-1111-111111111111",
    "EntraDeviceId": "22222222-2222-2222-2222-222222222222",
    "DeviceName": "PC-01",
    "SerialNumber": "ABC1234",
    "OperatingSystem": "Windows",
    "OsVersion": "10.0.26200.9711",
    "PrimaryUser": "user@contoso.com",
    "ComplianceState": "compliant",
    "ComplianceGracePeriodExpiration": "9999-12-31T23:59:59Z",
    "LastSync": "2026-11-03T09:20:27Z",
    "MatchedBy": "SerialNumber"
  },
  "Results": [
    {
      "PolicyId": "33333333-3333-3333-3333-333333333333",
      "PolicyName": "Huntress - Audit Policy Configuration",
      "Type": "Device Configuration",
      "PlatformType": "windows10AndLater",
      "Version": 1,
      "SettingCount": 59,
      "State": "error",
      "StateSource": "deviceConfigurationStates",
      "Contexts": [
        { "UserPrincipalName": "System account", "UserId": "00000000-0000-0000-0000-000000000000", "State": "error" },
        { "UserPrincipalName": "user@contoso.com", "UserId": "44444444-4444-4444-4444-444444444444", "State": "error" }
      ],
      "Settings": [
        {
          "Setting": "root\\ccm\\cimodels:CustomConfiguration.Key='./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditAuditPolicyChange',Type=20",
          "SettingName": "Windows10CustomConfiguration",
          "CspPath": "./Device/Vendor/MSFT/Policy/Config/Audit/PolicyChange_AuditAuditPolicyChange",
          "State": "error",
          "ErrorCode": -2016281112,
          "ErrorCodeHex": "0x87D1FDE8",
          "ErrorDescription": "2",
          "CurrentValue": null,
          "Contexts": ["System account", "user@contoso.com"]
        }
      ],
      "SettingsError": null,
      "Assignment": {
        "Status": "Applies", "Applies": true, "TargetedVia": "All Devices", "Filter": "",
        "FilterMode": "", "FilterResult": "", "ExcludedBy": "", "Notes": ""
      }
    },
    {
      "PolicyId": "55555555-5555-5555-5555-555555555555",
      "PolicyName": "Bitlocker",
      "Type": "Endpoint Security",
      "PlatformType": "windows",
      "Version": null,
      "SettingCount": null,
      "State": "notReported",
      "StateSource": null,
      "Contexts": [],
      "Settings": [],
      "SettingsError": null,
      "Assignment": { "Status": "Applies", "Applies": true, "TargetedVia": "All Devices", "Filter": "", "FilterMode": "", "FilterResult": "", "ExcludedBy": "", "Notes": "" }
    }
  ],
  "Summary": {
    "Profiles": 2,
    "Failing": 1,
    "NotReported": 1,
    "ByState": [ { "State": "error", "Count": 1 }, { "State": "notReported", "Count": 1 } ]
  },
  "Partial": false,
  "Errors": [],
  "Notes": ["1 profile(s) apply to this device but Graph's device state collections have no row for them (Settings Catalog, Endpoint Security and update profiles). Their state is unknown, not healthy."]
}
```

- `State` is Intune's `complianceStatus` (`compliant`, `notApplicable`, `remediated`, `nonCompliant`, `error`, `conflict`, `notAssigned`, `unknown`), worst across contexts, plus CIPP's `notReported`.
- **`notReported` means unknown, not healthy.** See the limits below.
- `Type` comes from the assignment evaluation: `Device Configuration`, `Administrative Templates`, `Settings Catalog`, `Endpoint Security`, and so on. It is null for a row the evaluation did not place, and for every row with `IncludeAssignments=false`.
- `Assignment` is CIPP's evaluation of assignments, groups and filters, not a statement from the device. An `Assignment.Status` other than `Applies` (`Excluded`, `Filtered out`) on a `notReported` row is expected and is not counted in `Summary.NotReported`.
- `CspPath` is parsed from `Setting`, and is null when the setting has no path. `ErrorDescription` is Graph's raw text, usually only a number such as `"2"`, so use `ErrorCodeHex`.

## ListDeviceComplianceState

```
GET /api/ListDeviceComplianceState?tenantFilter=contoso.com&DeviceId=22222222-2222-2222-2222-222222222222
```

```json
{
  "Device": { "ManagedDeviceId": "11111111-1111-1111-1111-111111111111", "DeviceName": "PC-01", "ComplianceState": "noncompliant", "MatchedBy": "EntraDeviceId" },
  "Results": [
    {
      "PolicyId": "66666666-6666-6666-6666-666666666666",
      "PolicyName": "Windows Compliance",
      "PlatformType": "windows10AndLater",
      "Version": 1,
      "SettingCount": 3,
      "State": "nonCompliant",
      "Contexts": [ { "UserPrincipalName": "System account", "UserId": "00000000-0000-0000-0000-000000000000", "State": "nonCompliant" } ],
      "Settings": [
        {
          "Setting": "",
          "SettingName": "Windows10CompliancePolicy.ActiveFirewallRequired",
          "CspPath": null,
          "State": "nonCompliant",
          "ErrorCode": 0,
          "ErrorCodeHex": null,
          "ErrorDescription": null,
          "CurrentValue": null,
          "Contexts": ["System account"]
        }
      ],
      "SettingsError": null
    }
  ],
  "Summary": { "Policies": 1, "Failing": 1, "ByState": [ { "State": "nonCompliant", "Count": 1 } ] },
  "Partial": false,
  "Errors": []
}
```

The built-in `Default Device Compliance Policy` appears here as a normal row. `Device` has the same fields as above and is shortened in this example.

## ListDeviceEffectivePolicy

```
GET /api/ListDeviceEffectivePolicy?tenantFilter=contoso.com&DeviceId=11111111-1111-1111-1111-111111111111
```

Returns the CIPP-19 evaluation with `Device.MatchedBy` and `Partial` added. This is a simulation from assignments, groups and filters, and it covers apps too. A live report for one Windows device held 48 rows.

```json
{
  "Device": { "ManagedDeviceId": "11111111-1111-1111-1111-111111111111", "EntraObjectId": "77777777-7777-7777-7777-777777777777", "EntraDeviceId": "22222222-2222-2222-2222-222222222222", "DeviceName": "PC-01", "Platform": "windows", "GroupTag": "corp", "DeviceGroups": ["All Devices"], "UserGroupCount": 12, "MatchedBy": "ManagedDeviceId" },
  "Results": [
    {
      "PolicyId": "88888888-8888-8888-8888-888888888888",
      "PolicyName": "Pin Copilot to taskbar",
      "PolicyType": "Settings Catalog",
      "Family": "ConfigurationPolicies",
      "Platform": "windows",
      "Intent": "",
      "Status": "Filtered out",
      "Applies": false,
      "TargetedVia": "All Devices",
      "Filter": "Devices supporting Start layout only",
      "FilterRule": "(device.operatingSystemVersion -ge 10.0.22621.5549)",
      "FilterMode": "exclude",
      "FilterResult": "Device matches rule",
      "ExcludedBy": "",
      "Notes": "",
      "DeviceStatus": ""
    }
  ],
  "Overlaps": [
    { "SettingDefinitionId": "device_vendor_msft_policy_config_defender_signatureupdateinterval", "Severity": "Conflict", "PolicyCount": 2, "Policies": "Defender | Defender Update", "Values": "Defender = 2 | Defender Update = 1" }
  ],
  "Summary": { "Applies": 46, "FilterUnknown": 0, "Excluded": 0, "FilteredOut": 2, "PlatformSkipped": 7, "PoliciesRead": 88, "Conflicts": 3, "Overlaps": 11 },
  "Errors": [],
  "Notes": [],
  "Partial": false
}
```

A device that is not Intune-managed returns 404 here. `ListIntuneEffectivePolicy` still shows what would target an Entra-only device.

## What Graph allows

Each row was read against one production device in aspendora.com on 2026-11-03. All reads were GET.

| Graph path (beta) | Result |
|---|---|
| `managedDevices/{id}/deviceConfigurationStates` | **Works.** One row per policy per context. `settingStates` is always `[]` here. |
| `managedDevices/{id}/deviceCompliancePolicyStates` | **Works**, same shape. |
| `.../deviceConfigurationStates/{policyId}/settingStates` | **Works.** Paged at 25, one row per setting per context. The only source of per-device error codes. |
| `.../deviceCompliancePolicyStates/{policyId}/settingStates` | **Works.** `setting` can be empty. |
| `managedDevices?$filter=azureADDeviceId eq '...'` | **Works.** A miss is an empty list. |
| `managedDevices?$filter=serialNumber eq '...'` | **Works.** A miss is an empty list. |
| `managedDevices/{id}` for an unknown id | Opaque "An error has occurred", not a clean 404. |
| `managedDevices?$filter=id eq '...'` | Fails with the same opaque error. |
| `.../deviceConfigurationStates/{policyId}` | Fails: no OData route. |
| `.../deviceConfigurationStates?$expand=settingStates` | Fails: not a navigation property. |
| `.../settingStates?$filter=state eq 'error'` | Fails, so filtering is client-side. |
| `deviceConfigurations/{id}/deviceStatuses` | Fails with a `$filter` by device name, and returned HTTP 500 unfiltered earlier the same day. Not used. |

## Limits

- **Settings Catalog, Endpoint Security and update profiles have no per-device state on these paths.** On the device tested, none of the 24 applying `ConfigurationPolicies` rows had a state row. They return `notReported`. Do not treat that as healthy.
- **Intune reports are not used.** Portal-style per-device reports need POST (`deviceManagement/reports/*`, `exportJobs`). This build was limited to verifying GET calls, so that surface is untested. It is the likely route to closing the gap above, and needs its own approval and verification.
- **`deviceConfigurationConflictSummary` is not used.** For contested settings, call `ListDevicePolicyConflicts` with the returned `ManagedDeviceId`. It takes a managed device id only, and it skips an unreadable collection or policy rather than reporting it, so an empty answer there is weaker than one here.
- **Read cost.** A configuration call with assignments reads every policy family plus group membership, the same work as the effective-policy page. Use `IncludeAssignments=false` for frequent polling. Graph's Intune data also lags the device's last check-in, so compare `Device.LastSync`.

## Testing and rollback

- Unit tests: `backend/Tests/Endpoint/DeviceStateIntegration.Tests.ps1`, with fixtures shaped from the live reads above.
- The endpoints themselves have not been called live: they exist only once this branch is deployed. After deploying, call each one for a known device and check against the table above.
- Rollback: revert the commit. The only change to existing behaviour is in `Get-CIPPIntuneEffectivePolicy`, which now reports a failed device status read in `Errors` instead of `Notes`, so it also shows as an error on the effective-policy page.
