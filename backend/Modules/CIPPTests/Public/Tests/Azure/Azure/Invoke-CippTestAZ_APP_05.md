Managed identities let the app reach databases, storage and Key Vault without stored secrets.

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

1. App → Identity → System assigned = On, then grant it roles instead of using connection-string secrets.

**Links**
- [Managed identities for App Service](https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity)

<!--- Results --->
%TestResult%
