# SMS/Voice MFA Readiness

This report answers one question before you turn on the **Disable SMS** or **Disable Voice** standard: who would be locked out? It reads the tenant's MFA registration report, its users and its authentication methods policy, and changes nothing.

Only enabled member accounts are counted. Email and security questions are not MFA methods and are ignored. A mobile phone can receive an SMS or a call; office phone and alternate mobile phone are voice only.

| Category     | Meaning                                                                                                                            |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| PhoneOnly    | Every MFA method the user has is a phone method. Disabling SMS and voice locks them out of MFA until they register something else. |
| DefaultPhone | The user has another method, but SMS or voice is their default. They keep working; their sign-in prompt changes.                   |
| NoMfa        | No MFA method at all. Not affected by the change, but a separate risk.                                                             |
| Ready        | Has a non-phone method as the default.                                                                                             |

## Summary

| Field                  | Meaning                                                                                                                                      |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Ready to disable SMS   | No enabled user relies only on phone methods with a mobile phone registered.                                                                 |
| Ready to disable voice | No enabled user relies only on voice numbers (office or alternate mobile), and, if SMS is already off, no phone-only user at all.            |
| Coverage               | Share of enabled users with Microsoft Authenticator (push or passwordless), a passkey or FIDO2 key, Windows Hello or a Platform Credential. |

## Findings

Admins with only SMS/voice, or with no MFA, are **Errors** (one row each). Admins who default to SMS/voice, users who rely only on SMS/voice (one consolidated row) and licensed users without MFA (one consolidated row) are **Warnings**. When SMS or voice is still enabled but nobody depends on it, an Info row says it can be turned off.

## Microsoft's SMS/voice retirement

Microsoft is retiring the SMS and voice it provides for Entra MFA (source: Microsoft Learn, *Passkeys by default and retirement of Microsoft-provided SMS and voice authentication*, read 2026-11-01):

| Date       | What happens                                                                                                                                                                                                          |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-09-01 | Users enabled for SMS/voice are auto-enabled for passkeys, and a Microsoft-managed registration campaign nudges them to register one (snoozable), unless the tenant set the temporary opt-out.                         |
| 2027-02-01 | Retired for everyone **except Global Administrators and external users**. Internal guests are in this group. A user whose **only** MFA method is SMS/voice then gets a **blocking** passkey registration at sign-in. No opt-out. |
| 2027-07-01 | The same for Global Administrators and external users.                                                                                                                                                                 |

A tenant can keep SMS/voice only through a telephony provider bought from Microsoft Security Store (from 2026-10-30). Users with any other MFA method, including an authenticator code (TOTP), are not blocked.

### How each user is dated

Every user with a phone method gets **RetirementDate**, **DaysRemaining** and **RetirementBasis**. Days are counted from today's date in US Central time and go negative once the date has passed.

| RetirementBasis             | Rule                                                                                                                                                                                               | Date       |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| GlobalAdministrator         | Active Global Administrator assignment, directly or through a role-assignable group.                                                                                                                | 2027-07-01 |
| GlobalAdministratorEligible | PIM-eligible for Global Administrator only (read only when the tenant has Entra ID P2). Microsoft has not said whether eligibility counts, so the July finding calls these out; treat them as February to be safe. | 2027-07-01 |
| ExternalUser                | An account from another organisation: the UPN contains `#EXT#`, or it has an invitation state, or it was created by invitation, or it signs in through ExternalAzureAD, a Microsoft account, email one-time passcode, Google or Facebook. Applies to guests and external members alike. | 2027-07-01 |
| InternalGuest               | userType Guest but none of the external signs above: an account that belongs to the tenant but is marked Guest.                                                                                    | 2027-02-01 |
| Member                      | Everyone else, including holders of admin roles other than Global Administrator.                                                                                                                    | 2027-02-01 |

If Global Administrator holders cannot be read, everyone is dated February (the earlier date) and an Info row says so.

Guests are still left out of every count above this section. Enabled guests whose only MFA is SMS/voice are listed in their own table and counted in the retirement figures.

### Retirement summary

| Field                          | Meaning                                                                                                                      |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| Deadline                       | The earliest retirement date that still has accounts relying only on SMS/voice, with how many, and the per-date counts.       |
| Days remaining                 | Days until that date (US Central). **Ready by 1 Feb 2027** is Yes when no February-group account relies only on SMS/voice.    |
| Opt-out                        | `optOutSettings.passkeyDynamicMigration` in the authentication methods policy: opted out, not opted out (also when never set), or unknown. The opt-out ends on 2027-02-01 and never stops enforcement. |
| Registration campaign          | State (Microsoft managed, enabled, disabled) and the method it targets, with whether Passkey (FIDO2) is enabled and for all users or only some groups. |
| TelephonyProvider (All Tenants) | `MicrosoftProvided` when the SMS and voice methods have no telecom provider setting, `Configured` when one is present, `NotDetectable` when the policy does not carry the setting. |

### Retirement findings

| Severity | Finding                                                                                                                                       |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Error    | N accounts will be blocked at sign-in from 2027-02-01 unless they register a passkey (a Warning instead if a telephony provider is configured). |
| Warning  | N Global Administrator or external accounts will be blocked from 2027-07-01.                                                                    |
| Info     | The tenant has opted out; the registration campaign is off or does not target passkeys; Passkey (FIDO2) is disabled or limited to groups; a telephony provider is configured; Global Administrators could not be read. |

## All Tenants

With **All Tenants** selected the page shows the result stored by the last check of each tenant: opening the tenant on this page, or a run of the **SMS/voice MFA reliance** alert. Tenants never checked are not listed.

{% hint style="info" %}
The registration report needs Microsoft Entra ID P1 (Business Premium, E3 or E5). Without it the page shows an error instead of results.
{% endhint %}

{% hint style="info" %}
Schedule the **SMS/voice MFA reliance** alert weekly under Alerts. It raises the same Error and Warning findings once each, and also alerts when Authenticator/passkey coverage drops more than 5 points (configurable) below its best. Its first run only records the coverage baseline.

Its rows also carry the retirement date and days remaining. Once the nearest retirement date that still has phone-only accounts is 90 days away or less (set **SmsRetirementWarnDays** to change it), it raises one row per tenant: an Error for 1 Feb 2027, a Warning for 1 Jul 2027. That row notifies once per date, not every week as the days count down, and resolves when those accounts are fixed. The other retirement findings are not alerted on their own.
{% endhint %}
