Soft delete keeps deleted backups for 14+ days, so an attacker who deletes backups before deploying ransomware cannot destroy them instantly.

**Frameworks** (indicative)

- Themes: Protection of backup data
- MCSB: BR-2
- CIS Controls v8: 11.3
- NIST CSF 2.0: PR.DS
- NIST 800-53: CP-9
- CMMC / 800-171: MP.L2-3.8.9
- SOC 2: A1.2
- ISO 27001: 8.13

**Remediation Action**

1. Vault → Properties → Security settings → Soft delete → Enable (consider "always-on").

**Links**
- [Backup security features](https://learn.microsoft.com/en-us/azure/backup/backup-azure-security-feature-cloud)

<!--- Results --->
%TestResult%
