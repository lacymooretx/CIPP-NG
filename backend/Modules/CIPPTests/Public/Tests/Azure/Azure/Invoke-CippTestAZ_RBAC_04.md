An app whose credential leaks becomes an attacker with that app's roles. Owner or User Access Administrator lets it grant itself or others anything. Third-party or unresolved apps with these roles fail; your own apps are flagged for review.

**Remediation Action**

1. Confirm each app needs access management; most automation only needs Contributor or a narrower role at resource-group scope.
2. Prefer managed identities over app registrations with secrets.
3. Rotate credentials of any app you keep.

**Links**
- [Azure RBAC best practices](https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices)

<!--- Results --->
%TestResult%
