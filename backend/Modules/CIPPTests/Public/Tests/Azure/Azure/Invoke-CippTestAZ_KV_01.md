Purge protection stops anyone, including an attacker with Owner, from permanently destroying keys and secrets during the retention period.

**Frameworks** (indicative)

- Themes: Protection of keys and secrets; Recovery of deleted or overwritten data
- MCSB: DP-8, BR-1
- CIS Controls v8: 11.1
- NIST CSF 2.0: PR.DS, RC.RP
- NIST 800-53: SC-12, CP-9
- CMMC / 800-171: SC.L2-3.13.10, MP.L2-3.8.9
- SOC 2: CC6.1, A1.2
- ISO 27001: 8.24, 8.13

**Remediation Action**

1. Key vault → Properties → Purge protection → Enable. This cannot be turned off afterwards.

**Links**
- [Soft-delete and purge protection](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview)

<!--- Results --->
%TestResult%
