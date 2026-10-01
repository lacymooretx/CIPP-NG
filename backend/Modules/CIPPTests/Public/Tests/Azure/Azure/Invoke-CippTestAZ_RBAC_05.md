A custom role with `*` in its actions is an Owner in disguise. It escapes reviews that look for the Owner role by name.

**Remediation Action**

1. Replace the custom role with the built-in role that matches the need, or list the specific actions it needs.
2. Re-assign affected principals, then delete the custom role.

**Links**
- [Azure custom roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles)

<!--- Results --->
%TestResult%
