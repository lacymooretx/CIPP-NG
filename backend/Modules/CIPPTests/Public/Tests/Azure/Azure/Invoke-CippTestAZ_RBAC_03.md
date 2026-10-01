When a user, group or app is deleted, its Azure role assignments stay behind. They grant nothing today but clutter access reviews and hide what access really exists. CSP/partner groups (ForeignGroup) are excluded because they never resolve in the client directory.

**Remediation Action**

1. In the portal, open Access control (IAM) → Role assignments at each scope listed, and remove the "Identity not found" entries.
2. Or: `az role assignment delete --ids <assignment id>`.

**Links**
- [Troubleshoot Azure RBAC: identity not found](https://learn.microsoft.com/en-us/azure/role-based-access-control/troubleshooting)

<!--- Results --->
%TestResult%
