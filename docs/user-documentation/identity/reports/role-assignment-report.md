# Role Assignment Report

This report lists every Microsoft Entra directory role assignment in the tenant, active and PIM-eligible, with role-assignable groups expanded to their members, and recommends least-privilege changes. It reads the tenant (and, for GDAP, the partner tenant) and changes nothing.

## Findings

| Check                         | Raised when                                                                                                                                                                                                      |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Standing Global Administrator | A user is a permanent active Global Administrator and is not a registered break-glass account. The message suggests smaller roles based on the Entra directory changes the account made in the last 30 days. |
| Service principal role        | A non-Microsoft app holds Global Administrator (Error) or another privileged role (Warning). Microsoft's own service principals are never flagged.                                                              |
| Guest with directory role     | A guest account holds a role (Warning if the role is privileged).                                                                                                                                               |
| Inactive privileged account   | A user with a privileged role has not signed in successfully for 45 days, or ever. Break-glass accounts are left to the break-glass posture check.                                                             |
| Disabled account with roles   | A disabled account still holds an active role.                                                                                                                                                                  |
| GDAP Global Administrator     | An active GDAP relationship with this customer includes Global Administrator; the message names the access assignments (security groups) that grant it.                                                        |

## Tables

* **Least-privilege recommendations**: one row per standing Global Admin with the suggested roles and the evidence. The Entra audit log does not record Exchange, Intune, SharePoint or Teams admin work, so check those against the task lookup.
* **All role assignments**: principal, role, whether it is privileged, active or eligible, permanent or time-bound, direct or through a group, last successful sign-in.
* **Least-privileged role by task**: the lookup used for the recommendations, from Microsoft Learn's "Least privileged roles by task in Microsoft Entra ID" (kept in `Config/LeastPrivilegeRoles.json`).

{% hint style="info" %}
PIM needs Microsoft Entra ID P2. Without it every active assignment is treated as standing, PIM-eligible assignments are not shown, and an Info finding says so. Sign-in activity needs Entra ID P1; without it the inactive-account check is skipped.
{% endhint %}

{% hint style="info" %}
Two weekly alerts build on this report: **Standing privileged access** raises the Error and Warning findings once each (with an allow-list for apps expected to hold roles), and **New role definitions** raises each custom directory role created after its first run.
{% endhint %}
