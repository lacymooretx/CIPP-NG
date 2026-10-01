Owner can change anything in a subscription, including who has access. Microsoft recommends no more than three owners, and at least two so access is never lost with one account.

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

1. Review the Owners listed below and remove any that are not needed.
2. Grant day-to-day administrators Contributor (or narrower) instead of Owner.
3. Where Entra ID P2 is available, make Owner eligible through PIM rather than permanent.

**Links**
- [Azure RBAC best practices](https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices)

<!--- Results --->
%TestResult%
