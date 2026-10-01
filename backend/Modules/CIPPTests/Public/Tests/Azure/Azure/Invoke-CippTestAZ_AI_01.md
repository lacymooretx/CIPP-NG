API keys for Azure OpenAI and other AI services are long-lived shared secrets; Entra authentication is auditable and revocable per identity.

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

1. Move callers to Entra ID (managed identity), then set disableLocalAuth = true.

**Links**
- [Disable local authentication](https://learn.microsoft.com/en-us/azure/ai-services/disable-local-auth)

<!--- Results --->
%TestResult%
