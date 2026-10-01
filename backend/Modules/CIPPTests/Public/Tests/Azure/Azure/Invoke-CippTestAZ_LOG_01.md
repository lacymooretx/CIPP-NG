Azure keeps the activity log (who created, changed or deleted what) for only 90 days. Exporting it to Log Analytics or storage keeps it for investigations.

**Frameworks** (indicative)

- Themes: Audit logging; Log retention
- MCSB: LT-3, LT-6
- CIS Controls v8: 8.2, 8.10
- NIST CSF 2.0: PR.PS, DE.CM
- NIST 800-53: AU-2, AU-12, AU-11
- CMMC / 800-171: AU.L2-3.3.1
- SOC 2: CC7.2
- ISO 27001: 8.15

**Remediation Action**

1. Monitor → Activity log → Export Activity Logs → Add diagnostic setting → all categories → client Log Analytics workspace.

**Links**
- [Azure activity log](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log)

<!--- Results --->
%TestResult%
