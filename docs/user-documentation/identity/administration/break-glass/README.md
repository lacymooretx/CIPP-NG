# Break-glass Accounts

This page manages the emergency-access (break-glass) accounts that CIPP watches. Every registered account is monitored by the **Break-glass account activity** alert, which raises a High alert for any sign-in (successful or failed, interactive or not), any directory change made to or by the account, and the account being disabled or deleted. It is also checked weekly by the **Break-glass posture** alert.

Registering or unregistering an account only changes what CIPP watches. Nothing on the account itself is changed.

## Page Actions

| Action           | Description                                                                                                                                                                       |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Register account | Registers a user (by user principal name or object id) in the selected tenant, with an optional note such as where its credentials are kept. Needs a single tenant selected.   |
| Suggest accounts | Looks for likely break-glass accounts: the user excluded from the most All-users Conditional Access policies, and accounts whose name looks like an emergency-access account. |

## Table Actions

| Action                   | Description                                                                  |
| ------------------------ | ---------------------------------------------------------------------------- |
| Unregister               | Stops watching the account. Its sign-ins and changes no longer raise alerts. |
| Register as break-glass  | (Suggestions table) Registers the suggested account.                         |

## Posture

The Posture tab runs the break-glass posture check for the selected tenant. It reports only and changes nothing. It checks that the tenant has at least two break-glass accounts; that each is cloud-only on the `onmicrosoft.com` domain, a permanent active Global Administrator, excluded from every enabled Conditional Access policy (with users, groups and roles resolved), set to never expire its password, protected by FIDO2 with no person-bound MFA method, and signed in to within the last 90 days. It also lists other accounts excluded from many All-users policies.

{% hint style="info" %}
The alerts only cover tenants they are scheduled for. Schedule **Break-glass account activity** (every 30 minutes) and **Break-glass posture** (weekly) under Alerts for the tenants you manage.
{% endhint %}
