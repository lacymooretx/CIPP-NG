Azure keeps the activity log (who created, changed or deleted what) for only 90 days. Exporting it to Log Analytics or storage keeps it for investigations.

**Remediation Action**

1. Monitor → Activity log → Export Activity Logs → Add diagnostic setting → all categories → client Log Analytics workspace.

**Links**
- [Azure activity log](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)

<!--- Results --->
%TestResult%
