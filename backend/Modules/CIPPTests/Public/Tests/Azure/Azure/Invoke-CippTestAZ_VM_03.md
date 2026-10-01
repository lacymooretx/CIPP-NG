VMs without backup cannot be recovered after ransomware or accidental deletion. Flagged for review because some clients back up VMs with a third-party product.

**Remediation Action**

1. Recovery Services vault → Backup → Azure Virtual Machine → select the listed VMs with an appropriate policy.
2. If another product (e.g. Veeam) backs these VMs up, record that in IT Glue.

**Links**
- [Azure VM backup](https://learn.microsoft.com/en-us/azure/backup/backup-azure-vms-introduction)

<!--- Results --->
%TestResult%
