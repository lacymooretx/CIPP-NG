Local cluster accounts bypass Entra ID, MFA and Conditional Access, and cannot be revoked per person.

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

1. Enable Entra integration, then `az aks update --disable-local-accounts`.

**Links**
- [Manage local accounts in AKS](https://learn.microsoft.com/en-us/azure/aks/manage-local-accounts-managed-azure-ad)

<!--- Results --->
%TestResult%
