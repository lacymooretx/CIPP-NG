Without audit logs there is no record of who read which secret, which is the first question after an incident.

**Remediation Action**

1. Key vault → Diagnostic settings → Add → category group "audit" → send to the client Log Analytics workspace.

**Links**
- [Key Vault logging](https://learn.microsoft.com/en-us/azure/key-vault/general/logging)

<!--- Results --->
%TestResult%
