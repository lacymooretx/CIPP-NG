Alerts on these operations catch someone opening a firewall, deleting a policy or exposing a public IP, typical steps before or during an attack.

**Frameworks** (indicative)

- Themes: Alerting on security-relevant changes
- MCSB: LT-1
- CIS Controls v8: 8.11
- NIST CSF 2.0: DE.CM, DE.AE
- NIST 800-53: AU-6, SI-4
- CMMC / 800-171: SI.L2-3.14.6
- SOC 2: CC7.2
- ISO 27001: 8.16

**Remediation Action**

1. Monitor → Alerts → Create → Activity log alert, one per operation (or one rule per resource type), with an action group that emails or tickets the MSP.
2. An Azure Policy (DeployIfNotExists) or a script can create them consistently across clients.

**Links**
- [Activity log alerts](https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts)

<!--- Results --->
%TestResult%
