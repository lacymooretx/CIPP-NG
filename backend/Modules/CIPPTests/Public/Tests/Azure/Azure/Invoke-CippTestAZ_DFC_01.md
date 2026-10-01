Without the Microsoft.Security provider, a subscription has no Defender for Cloud at all: no secure score, no recommendations, no security alerts.

**Remediation Action**

1. Open Microsoft Defender for Cloud in the portal with the subscription selected. This registers the provider and enables the free foundational CSPM.
2. Or: `az provider register --namespace Microsoft.Security --subscription <id>`.

**Links**
- [Enable Defender for Cloud on a subscription](https://learn.microsoft.com/en-us/azure/defender-for-cloud/connect-azure-subscription)

<!--- Results --->
%TestResult%
