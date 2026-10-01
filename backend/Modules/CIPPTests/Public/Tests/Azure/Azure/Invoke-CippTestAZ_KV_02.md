Vault access policies sit outside Azure RBAC: they are not covered by PIM, role reviews or deny assignments, and anyone with Contributor can edit them.

**Remediation Action**

1. Map existing access policies to Key Vault RBAC roles, then Access configuration → Azure role-based access control.

**Links**
- [Migrate to Azure RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-migration)

<!--- Results --->
%TestResult%
