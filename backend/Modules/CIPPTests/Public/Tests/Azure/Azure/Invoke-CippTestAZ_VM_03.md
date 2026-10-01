VMs without backup cannot be recovered after ransomware or accidental deletion. Flagged for review because some clients back up VMs with a third-party product.

**Frameworks** (indicative)

- Themes: Backup coverage and monitoring
- MCSB: BR-1, BR-3
- CIS Controls v8: 11.2
- NIST CSF 2.0: PR.DS, RC.RP
- NIST 800-53: CP-9
- CMMC / 800-171: MP.L2-3.8.9
- SOC 2: A1.2
- ISO 27001: 8.13

**Remediation Action**

1. Recovery Services vault → Backup → Azure Virtual Machine → select the listed VMs with an appropriate policy.
2. If another product (e.g. Veeam) backs these VMs up, record that in IT Glue.

**Links**
- [Azure VM backup](https://learn.microsoft.com/en-us/azure/backup/backup-azure-vms-introduction)

<!--- Results --->
%TestResult%
