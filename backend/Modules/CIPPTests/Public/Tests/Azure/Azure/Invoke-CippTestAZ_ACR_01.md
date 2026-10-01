The registry admin user is a single shared credential with push/pull rights.

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

1. Use Entra identities or tokens, then Registry → Access keys → Admin user = off.

**Links**
- [Registry authentication](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication)

<!--- Results --->
%TestResult%
