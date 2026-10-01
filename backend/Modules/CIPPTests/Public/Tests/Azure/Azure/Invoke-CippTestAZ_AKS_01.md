Local cluster accounts bypass Entra ID, MFA and Conditional Access, and cannot be revoked per person.

**Remediation Action**

1. Enable Entra integration, then `az aks update --disable-local-accounts`.

**Links**
- [Manage local accounts in AKS](https://learn.microsoft.com/en-us/azure/aks/manage-local-accounts-managed-azure-ad)

<!--- Results --->
%TestResult%
