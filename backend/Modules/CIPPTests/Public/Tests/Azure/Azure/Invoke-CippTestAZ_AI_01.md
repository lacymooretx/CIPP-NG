API keys for Azure OpenAI and other AI services are long-lived shared secrets; Entra authentication is auditable and revocable per identity.

**Remediation Action**

1. Move callers to Entra ID (managed identity), then set disableLocalAuth = true.

**Links**
- [Disable local authentication](https://learn.microsoft.com/en-us/azure/ai-services/disable-local-auth)

<!--- Results --->
%TestResult%
