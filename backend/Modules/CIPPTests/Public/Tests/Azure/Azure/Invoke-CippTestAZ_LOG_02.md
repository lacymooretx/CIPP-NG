Alerts on these operations catch someone opening a firewall, deleting a policy or exposing a public IP, typical steps before or during an attack.

**Remediation Action**

1. Monitor → Alerts → Create → Activity log alert, one per operation (or one rule per resource type), with an action group that emails or tickets the MSP.
2. An Azure Policy (DeployIfNotExists) or a script can create them consistently across clients.

**Links**
- [Activity log alerts](https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/activity-log-alerts)

<!--- Results --->
%TestResult%
