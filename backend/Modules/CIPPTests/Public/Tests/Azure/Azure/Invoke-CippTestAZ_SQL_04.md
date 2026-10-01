SQL logins are passwords without MFA. Entra-only authentication removes them. Many line-of-business apps still need a SQL login, so this is flagged for review.

**Frameworks** (indicative)

- Themes: Centralised identity-based authentication (no shared keys or local accounts)
- MCSB: IM-1, IM-3
- CIS Controls v8: 6.7
- NIST CSF 2.0: PR.AA
- NIST 800-53: IA-2, IA-5
- CMMC / 800-171: IA.L1-3.5.2
- SOC 2: CC6.1
- ISO 27001: 8.5

**Remediation Action**

1. After apps move to managed identity or Entra logins: SQL server → Microsoft Entra ID → "Support only Microsoft Entra authentication".

**Links**
- [Entra-only authentication](https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-azure-ad-only-authentication)

<!--- Results --->
%TestResult%
