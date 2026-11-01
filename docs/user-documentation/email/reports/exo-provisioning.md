# Exchange Provisioning

Checks that Exchange Online provisioned correctly in the selected tenant. Run it after onboarding a tenant or adding a SKU. Exchange can fail silently: the reported case was new tenants on E7 where the Exchange RBAC roles were never created and the organisation did not provision, which only showed up when mailbox creation broke during onboarding.

Press **Run check**. The page reads the tenant live and changes nothing. The only write is the **Repair Exchange roles** button, which asks for confirmation first.

## Checks

| Check | Pass when | Fail / Warn |
| ----- | --------- | ----------- |
| ExchangeLicence | An active subscription has a mailbox service plan (for example EXCHANGE_S_STANDARD, EXCHANGE_S_ENTERPRISE, EXCHANGE_S_DESKLESS) in status Success. | Fail if the plan is in Error, Warn while it is still pending. No mailbox plan at all is Info, not a failure. |
| OrganizationConfig | `Get-OrganizationConfig` answers. | Fail when the tenant is licensed for Exchange but Exchange does not answer (Warn if the tenant is younger than the grace period). |
| OrganizationCustomization | Info only: the organisation is dehydrated, which is normal for small tenants. | - |
| RoleGroups | The built-in role groups exist (Organization Management, Recipient Management, View-Only Organization Management, Help Desk, Hygiene Management, Compliance Management, Discovery Management, Records Management, Security Administrator, Security Reader). | Fail if none exist or Organization Management is missing, Warn for others. |
| ManagementRoles | Core management roles exist (Mail Recipient Creation, Mail Recipients, Organization Configuration, Role Management, and others). | Fail if any is missing. |
| OrgManagementRoles | Organization Management holds every role it should. This is the same comparison as the Tenant access check. | Fail if 5 or more are missing, Warn for 1 to 4. |
| AcceptedDomains | Every verified domain with the Email service in Entra is an accepted domain in Exchange. | Fail if there are no accepted domains or the onmicrosoft.com domain is missing, Warn per missing domain. |
| LicensedUserMailboxes | Every member licensed for a mailbox for longer than 24 hours has an Exchange recipient. | Fail if none of them do (the whole tenant is failing), Warn for individual users. Licensed mail users (hybrid, mailbox on-premises) are noted, not failed. |

When Exchange does not answer, the remaining checks show as skipped. A check that could not be read (for example a missing permission) shows as Warn with the error.

## Fixing problems

* **Organization Management missing roles:** press **Repair Exchange roles** (needs the CIPP.AppSettings.ReadWrite role), or use **Repair Exchange Roles** on the Tenant access check (CIPP > Settings > Permissions). Wait about 15 minutes, then run the check again. The repair needs the RoleManagement.ReadWrite.Exchange application permission.
* **Exchange not answering, role groups or management roles missing:** if the tenant or SKU was added within the last day, wait and check again. Otherwise open a Microsoft support case: the role repair cannot create role groups or an organisation that does not exist.
* **Domain not accepted:** domains normally reach Exchange within an hour of verification. Re-save the domain in the Microsoft 365 admin center with the Exchange service selected.
* **Licensed user with no mailbox:** check the user in the Microsoft 365 admin center for a provisioning error (duplicate proxy address, ExchangeGuid conflict, hybrid user without msExchMailboxGuid), fix the cause, then remove and re-add the licence.

## Alert

The **Alert when Exchange Online did not provision correctly** scripted alert (`ExoProvisioning`, recommended daily) raises every Fail and Warn finding once and resolves it when fixed. Each missing domain and each user without a mailbox is a separate finding; when no licensed user has a mailbox, one tenant-level finding is raised instead. Tenants without an Exchange licence produce nothing. The alert never runs the repair.

{% hint style="info" %}
Aspendora fork addition (Vikunja CIPP-36). Endpoint: `/api/ListExoProvisioningHealth?tenantFilter=<tenant>&graceHours=24` (Exchange.Mailbox.Read). Repair: `/api/ExecExchangeRoleRepair` (CIPP.AppSettings.ReadWrite).
{% endhint %}
