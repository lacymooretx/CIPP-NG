# Entra ID P1/P2 True-Up

This report answers one question: does the tenant own enough Entra ID seats for the users its Conditional Access policies cover? Conditional Access needs Entra ID P1. Risk-based policies (sign-in risk and user risk) need Entra ID P2. The report is read-only.

## How it counts

| Item | Rule |
| --- | --- |
| Seats owned | Enabled units of every SKU carrying the plan, counted by service plan and not SKU name. P2 seats also count as P1. Suspended units count as nothing. |
| In scope | Enabled member users covered by the user assignment of at least one enforced policy. Apps, locations and platforms are not considered, so this is the worst case. |
| Short | Users in scope minus seats owned. This is the only thing the alert raises. |
| No plan assigned | In scope with no enabled plan on the account. Advisory evidence for a true-up, not a failure. |
| Report-only policies | Left out of the shortfall. Shown as what enabling them would need. |
| Guests | Billed on monthly active users. Reported, never counted against seats. |
| Shared and resource mailboxes | Left out and reported, using CIPP's cached mailbox data. A note appears if that cache is empty. |
| Workload identity policies | Not counted: they have their own licence. |

A holder of two SKUs counts twice in seats owned, so the seat count is the most generous reading. PIM-eligible role holders count as role holders.

## All tenants

With **All Tenants** selected, the page shows the summary stored by the last single-tenant view or alert run. Tenants never checked are not listed.

## Alert and test

- **Alert:** "Alert when Entra ID P1/P2 seats do not cover the users in scope of Conditional Access" (`EntraEntitlementGap`). Recommended weekly. It notifies once per shortfall and resolves when fixed. It is not scheduled by default.
- **Test:** `GenericTestEntraEntitlement` in the Generic Tenant Tests suite reads the stored summary, so it is skipped until the tenant has been checked once.

## Sources

- [Conditional Access license requirements](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview#license-requirements)
- [External ID pricing](https://learn.microsoft.com/en-us/entra/external-id/external-identities-pricing)
