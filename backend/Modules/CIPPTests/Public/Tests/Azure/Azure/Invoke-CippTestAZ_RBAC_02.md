Guest accounts are governed by another organisation: their password policy, MFA and offboarding are outside your control. They should not hold write or access-management roles on client subscriptions.

**Frameworks** (indicative)

- Themes: Control of guest and third-party identities; Least privilege for administrative roles
- MCSB: PA-1, PA-7
- CIS Controls v8: 5.4, 6.8
- NIST CSF 2.0: PR.AA
- NIST 800-53: AC-2, AC-6, AC-6(5)
- CMMC / 800-171: AC.L2-3.1.5
- SOC 2: CC6.2, CC6.3
- ISO 27001: 5.18, 8.2

**Remediation Action**

1. Remove the guest assignments listed, or replace them with a member account in this tenant.
2. If a partner needs access, use Azure Lighthouse or a scoped, time-limited assignment.

**Links**
- [Azure RBAC best practices](https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices)

<!--- Results --->
%TestResult%
