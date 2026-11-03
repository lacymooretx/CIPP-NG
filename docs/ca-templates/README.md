# Aspendora CA baseline: token theft / AiTM and risk policies (Vikunja CIPP-8)

Graph `conditionalAccessPolicy` bodies for `POST /identity/conditionalAccess/policies` (v1.0 or beta), in the same
shape as `backend/Config/*.CATemplate.json`. They can be imported as CIPP CA templates or posted directly.

Every policy:

- has `state: enabledForReportingButNotEnforced` (report-only). Review the report-only results in the sign-in
  logs (Conditional Access > Report-only tab, or Insights and reporting) for at least a week before enforcing.
- is named `Aspendora - <purpose> (CIPP-8)`.
- leaves `excludeUsers` and `excludeGroups` empty. **Add the tenant's break-glass group to `excludeGroups` at
  deploy time**, plus any exclusions the review turns up. Never enforce without the break-glass exclusion.

## Files

| File | What it does | Licence |
|---|---|---|
| `01-token-protection-windows.CATemplate.json` | Token Protection (`sessionControls.secureSignInSession`) for Windows desktop apps (`clientAppTypes: mobileAppsAndDesktopClients`, `platforms: windows`) signing in to Exchange Online (`00000002-0000-0ff1-ce00-000000000000`), SharePoint Online (`00000003-0000-0ff1-ce00-000000000000`) and Microsoft Teams Services (`cc15fd57-2c6c-4117-a88c-83b1d56b4bbe`). The sign-in session is bound to the device, so a stolen refresh token replayed elsewhere is refused. | Entra ID P1 |
| `02-block-device-code-auth-transfer.CATemplate.json` | Blocks the device code flow and authentication transfer (`conditions.authenticationFlows.transferMethods = "deviceCodeFlow,authenticationTransfer"`) for all users and apps. Device-code phishing hands the attacker a token without an MFA prompt of their own. | Entra ID P1 |
| `03-sif-unmanaged-devices.CATemplate.json` | Sign-in frequency 12 hours and persistent browser `never` on devices matching `device.isCompliant -ne True -and device.trustType -ne "ServerAD"` (not compliant and not hybrid joined). Shortens how long a stolen session cookie from an unmanaged device stays useful. | Entra ID P1 |
| `04-admin-portals-managed-device.CATemplate.json` | Microsoft Admin Portals (`MicrosoftAdminPortals`) require a compliant **or** hybrid-joined device (`compliantDevice` OR `domainJoinedDevice`) for 18 admin roles: Global Admin, Privileged Role Admin, Privileged Authentication Admin, Security Admin, Conditional Access Admin, Exchange Admin, SharePoint Admin, User Admin, Helpdesk Admin, Authentication Admin, Password Admin, Billing Admin, Application Admin, Cloud Application Admin, Intune Admin, Teams Admin, Hybrid Identity Admin, Global Reader. | Entra ID P1 (+ Intune for compliance) |
| `05-signin-risk-medium-high-mfa.CATemplate.json` | Sign-in risk medium or high: require MFA, with sign-in frequency `everyTime` (Microsoft's recommended shape, so the MFA is fresh rather than satisfied by an existing session claim). | **Entra ID P2** |
| `06-signin-risk-high-block.CATemplate.json` | Sign-in risk high: block. Together with 05, high-risk sign-ins are blocked (block wins) and medium-risk sign-ins must do MFA. | **Entra ID P2** |
| `07-user-risk-high-password-change.CATemplate.json` | User risk high: require MFA **and** a secure password change (`operator: AND`, `mfa` + `passwordChange`), sign-in frequency `everyTime`. This is Microsoft's "Require secure password change for elevated user risk" template. | **Entra ID P2** |

## CIPP-7 and Microsoft Authenticator Credential Registration (Vikunja CIPP-53)

`cipp7-phishres-admins.json` excludes `6aa00308-ea33-4caa-90d6-ae905d8cb51b`, Microsoft Authenticator Credential
Registration. Microsoft Learn documents that an All resources policy requiring a phishing-resistant strength stops
people registering a passkey in Authenticator, and the built-in strength does not allow a Temporary Access Pass.

- **This file only.** The exclusion is on this template because it matches Learn's pattern. Do not copy it to MFA,
  risk or block policies. Live policies and the template stored in CIPP's table (`ca58640f`) are unchanged: re-import
  the file when you are ready, and only then does a deployment carry the exclusion.
- **A missing service principal cannot drop it.** `New-CIPPCAPolicy` removes excluded apps with no service principal
  in the tenant, and now logs a warning when it does. This app is the exception: it is provisioned instead, and if
  that fails the deployment throws. The standard `AuthenticatorCredentialRegistration` provisions it ahead of time.
- **What it costs.** It lets someone reach registration without phishing-resistant sign-in, and no tenant had a
  Register security info policy as of 2026-11-03. Add one before enforcing. The gap analysis check
  `Test-CIPPCAGapAuthenticatorRegistration` flags the matching policies, enforced and report-only separately, and a
  missing Register security info policy. `Test-CIPPCAGapResourceExclusionBypass` raises a finding once this is on an
  enforced policy, unless a policy covers Azure AD Graph.
- **Test:** `pwsh backend/Tests/Invoke-CippTests.ps1 -Path Tests/Standards/Invoke-CIPPStandardAuthenticatorCredentialRegistration.Tests.ps1`,
  and the same for `Tests/Security/AuthenticatorRegistrationBlock.Tests.ps1` and
  `Tests/Private/New-CIPPCAPolicy.RequiredExclusions.Tests.ps1`.
- **Rollback:** set `excludeApplications` back to `[]`. Provisioned service principals carry no permissions and can
  stay.

## Licensing summary

- **P2 needed:** 05, 06, 07 (any policy using `signInRiskLevels` or `userRiskLevels`). On a tenant without P2
  the policy can be created but never matches; do not count it as protection.
- **P1 needed:** 01, 02, 03, 04 (Conditional Access itself). 04 also needs Intune enrolment/compliance policies
  (or hybrid join) for users to satisfy it.
- For non-P2 tenants, the `NewRiskyUsers` alert now falls back to `identityProtection/riskDetections` (see
  "Related code" below), but that is detection after the fact, not a policy.

## Risks and things that break

- **Token Protection (01)** is enforced only on supported clients: Windows, desktop apps that use WAM (new and
  classic Outlook on current builds, Teams, OneDrive, the Office apps). Unsupported clients are **blocked**, not
  skipped: older Office builds, third-party mail clients, PowerShell modules and scripts that sign in as the user
  to EXO/SPO/Teams, and devices that are not Entra joined, hybrid joined or registered. Browsers are not covered
  (`clientAppTypes` is desktop only). Check the report-only results for `secureSignInSession` failures and
  exclude the affected users or devices before enforcing.
- **Device code block (02)** breaks: Microsoft Teams Rooms / Teams Android devices and other shared devices that
  sign in with a code, `az login --use-device-code`, `Connect-MgGraph -UseDeviceAuthentication`,
  `Connect-ExchangeOnline -Device`, and some conference-room and printer integrations. Authentication transfer
  (signing in to mobile Outlook by scanning a QR code from desktop Outlook) also stops working. Run
  **ListDeviceCodeSignIns** for the tenant first and exclude the legitimate accounts (resource accounts, a named
  admin) by group.
- **Sign-in frequency on unmanaged devices (03)** prompts personal-device and BYOD users to sign in again every
  12 hours and stops "stay signed in" in their browsers. The device filter only sees device state on sign-ins
  that carry it; a sign-in with no device information counts as unmanaged.
- **Admin portals (04)** locks admins out of the Entra, Microsoft 365, Exchange, Intune, Azure and other admin
  portals from any device that is not compliant or hybrid joined, including personal devices and jump boxes
  that are not enrolled. GDAP/partner access comes from the partner tenant's sign-ins and is not targeted by
  role assignments in the customer tenant, but confirm in report-only first. The break-glass group exclusion
  is essential here.
- **Risk policies (05-07)** need P2. 06 blocks outright, so a false-positive high sign-in risk locks the user out
  until an admin dismisses the risk; 07 requires the user to be registered for MFA and, for synced users,
  password writeback (or Entra Connect password hash sync with on-premises password change allowed). Microsoft
  also offers a newer `riskRemediation` grant control ("Require risk remediation") for user risk, which lets
  passwordless users remediate without a password change; it is not used here because the CIPP-8 request was
  password change + MFA.

## Graph property names (verified)

Verified against `backend/Config/graph-metadata/v1.0.xml` and `beta.xml` (2026-10-31):

- `conditionalAccessSessionControls.secureSignInSession` of type `secureSignInSessionControl` (only `isEnabled`).
  Present in **both v1.0 and beta**, so the token-protection body works on either.
- `conditionalAccessConditionSet.authenticationFlows.transferMethods` is a flags enum
  `conditionalAccessTransferMethods` with members `none, deviceCodeFlow, authenticationTransfer`, so the combined
  value is the comma string `"deviceCodeFlow,authenticationTransfer"`.
- `signInFrequencySessionControl`: `frequencyInterval` (`timeBased`/`everyTime`), `type` (`hours`/`days`),
  `value`, `authenticationType` (`primaryAndSecondaryAuthentication`).
- `persistentBrowserSessionControl.mode` (`always`/`never`).
- Grant controls used: `block`, `mfa`, `compliantDevice`, `domainJoinedDevice`, `passwordChange`.

Shapes 02, 05 and 07 also match the policies already live in the Aspendora tenant ("BPA - Block device code
flow and authentication transfer", "BPA - Sign-in risk (medium+high) - Require MFA", "BPA - User risk (high) -
Require secure password change"), read back on 2026-10-31. Role template IDs and the three app IDs were read
from `directoryRoleTemplates` and `servicePrincipals` in the Aspendora tenant.

## Related code

- `GET /api/ListDeviceCodeSignIns?tenantFilter=<tenant>&Days=30` (core: `Get-CIPPDeviceCodeSignIns`): device-code
  sign-ins per user + app + device, walked one day at a time because the `authenticationProtocol` filter is
  unindexed and times out over 30 days. Returns `Licensed = false` with a message on tenants without P1.
- `Get-CIPPAlertNewRiskyUsers`: on tenants without P2 it now reports new medium/high/hidden risk detections from
  `identityProtection/riskDetections` (last 7 days, once per detection) instead of returning silently.

## Rollback

Delete the policy, or set its `state` to `disabled`. Report-only policies have no user impact.
