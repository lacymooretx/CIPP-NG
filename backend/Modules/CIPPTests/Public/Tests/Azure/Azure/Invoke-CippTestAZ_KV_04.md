Without audit logs there is no record of who read which secret, which is the first question after an incident.

**Frameworks** (indicative)

- Themes: Audit logging
- MCSB: LT-3
- CIS Controls v8: 8.2
- NIST CSF 2.0: PR.PS, DE.CM
- NIST 800-53: AU-2, AU-12
- CMMC / 800-171: AU.L2-3.3.1
- SOC 2: CC7.2
- ISO 27001: 8.15

**Remediation Action**

1. Key vault → Diagnostic settings → Add → category group "audit" → send to the client Log Analytics workspace.

**Links**
- [Key Vault logging](https://learn.microsoft.com/en-us/azure/key-vault/general/logging)

<!--- Results --->
%TestResult%
