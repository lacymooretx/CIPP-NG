An app whose credential leaks becomes an attacker with that app's roles. Owner or User Access Administrator lets it grant itself or others anything. Third-party or unresolved apps with these roles fail; your own apps are flagged for review.

**Frameworks** (indicative)

- Themes: Least privilege for administrative roles; Control of guest and third-party identities
- MCSB: PA-1, PA-7
- CIS Controls v8: 5.4, 6.8
- NIST CSF 2.0: PR.AA
- NIST 800-53: AC-6, AC-6(5), AC-2
- CMMC / 800-171: AC.L2-3.1.5
- SOC 2: CC6.3, CC6.2
- ISO 27001: 8.2, 5.18

**Remediation Action**

1. Confirm each app needs access management; most automation only needs Contributor or a narrower role at resource-group scope.
2. Prefer managed identities over app registrations with secrets.
3. Rotate credentials of any app you keep.

**Links**
- [Azure RBAC best practices](https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices)

<!--- Results --->
%TestResult%
