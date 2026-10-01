Without the Microsoft.Security provider, a subscription has no Defender for Cloud at all: no secure score, no recommendations, no security alerts.

**Frameworks** (indicative)

- Themes: Threat detection and endpoint protection; Secure configuration baseline and posture assessment
- MCSB: LT-1, ES-1, PV-1, PV-2
- CIS Controls v8: 10.1, 13.1, 4.1
- NIST CSF 2.0: DE.CM, PR.PS, ID.RA
- NIST 800-53: SI-3, SI-4, CM-6, RA-5
- CMMC / 800-171: SI.L1-3.14.2, SI.L2-3.14.6, CM.L2-3.4.2, RA.L2-3.11.2
- SOC 2: CC6.8, CC7.2, CC7.1
- ISO 27001: 8.7, 8.16, 8.8, 8.9

**Remediation Action**

1. Open Microsoft Defender for Cloud in the portal with the subscription selected. This registers the provider and enables the free foundational CSPM.
2. Or: `az provider register --namespace Microsoft.Security --subscription <id>`.

**Links**
- [Enable Defender for Cloud on a subscription](https://learn.microsoft.com/en-us/azure/defender-for-cloud/connect-azure-subscription)

<!--- Results --->
%TestResult%
