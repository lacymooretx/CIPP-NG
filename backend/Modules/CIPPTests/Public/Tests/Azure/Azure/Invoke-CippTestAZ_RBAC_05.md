A custom role with `*` in its actions is an Owner in disguise. It escapes reviews that look for the Owner role by name.

**Frameworks** (indicative)

- Themes: Least privilege for administrative roles
- MCSB: PA-1, PA-7
- CIS Controls v8: 5.4, 6.8
- NIST CSF 2.0: PR.AA
- NIST 800-53: AC-6, AC-6(5)
- CMMC / 800-171: AC.L2-3.1.5
- SOC 2: CC6.3
- ISO 27001: 8.2

**Remediation Action**

1. Replace the custom role with the built-in role that matches the need, or list the specific actions it needs.
2. Re-assign affected principals, then delete the custom role.

**Links**
- [Azure custom roles](https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles)

<!--- Results --->
%TestResult%
