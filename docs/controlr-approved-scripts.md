# Approved ControlR scripts from CIPP

Aspendora fork addition. `/api/ExecControlRApprovedScript` runs a named read-only ControlR script on an Intune-managed device. Role: `Endpoint.MEM.ReadWrite`.

| Action | Method | Parameters | Returns |
|---|---|---|---|
| `List` | GET | none | Approved scripts and tenants |
| `Run` | POST | `tenantFilter`, `ScriptKey`, `DeviceId` or `SerialNumber` | `RunId`, `Status`, `Device`, `MatchMethod` |
| `Status` | GET | `RunId` | ControlR's run record with each device's output |

Script keys: `CountSavedBrowserLogins`, `IdentifyCopilotInstall`. Tenants: `aspendora.com`.

## Limits

- A script or tenant not listed in the endpoint gets 403 before any other call.
- A device CIPP cannot resolve returns 400, 404 or 409 from `Resolve-CIPPManagedDevice`. Nothing runs.
- If ControlR's match disagrees on tenant or Intune device, the endpoint returns 409 and nothing runs.
- ControlR enforces its own script allow-list and tenant limit. The token cannot reach other ControlR APIs.
- Each run, and each ControlR refusal, is written to the CIPP log as `CIPP integration: ...`.

## Token

Keeper record "env: CIPP Integration" (`NRS7H6W_5MJ3F_t49-qEvA`) is the source. CIPP reads a copy from key vault secret `ControlRIntegration` and caches it in the process. Expires 2027-05-02. After rotating: update the vault secret and restart the app.

## Adding a script

Needs Lacy's approval, especially for anything that changes a device, then a change in both `$ApprovedScripts` here and `ApprovedIntegrationScriptIds` in ControlR.

## Testing

`Invoke-Pester backend/Tests/Endpoint/Invoke-ExecControlRApprovedScript.Tests.ps1`. Live: `Action=List`, then `Run` on a test device, then `Status`.

## Rollback

Disable by deleting the vault secret and restarting: every call then returns 500 and nothing runs. Or revert the commit.
