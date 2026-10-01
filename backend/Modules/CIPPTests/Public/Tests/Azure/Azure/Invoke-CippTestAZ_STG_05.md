Account keys never expire and grant full access. Disabling them forces Entra ID authentication. Many tools still need keys, so this is flagged for review rather than failed.

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

1. Confirm nothing uses the account keys or account-key SAS, then Configuration → Allow storage account key access = Disabled.

**Links**
- [Prevent Shared Key authorization](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent)

<!--- Results --->
%TestResult%
