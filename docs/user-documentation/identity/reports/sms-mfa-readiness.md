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

## All Tenants

With **All Tenants** selected the page shows the result stored by the last check of each tenant: opening the tenant on this page, or a run of the **SMS/voice MFA reliance** alert. Tenants never checked are not listed.

{% hint style="info" %}
The registration report needs Microsoft Entra ID P1 (Business Premium, E3 or E5). Without it the page shows an error instead of results.
{% endhint %}

{% hint style="info" %}
Schedule the **SMS/voice MFA reliance** alert weekly under Alerts. It raises the same Error and Warning findings once each, and also alerts when Authenticator/passkey coverage drops more than 5 points (configurable) below its best. Its first run only records the coverage baseline.
{% endhint %}
