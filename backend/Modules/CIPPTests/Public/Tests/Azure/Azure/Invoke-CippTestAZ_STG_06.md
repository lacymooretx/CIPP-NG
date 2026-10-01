Cross-tenant object replication can copy data continuously to a storage account in another organisation.

**Frameworks** (indicative)

- Themes: Restricting public and network access to data stores
- MCSB: NS-2
- CIS Controls v8: 3.3
- NIST CSF 2.0: PR.DS, PR.AA
- NIST 800-53: AC-3, SC-7
- CMMC / 800-171: AC.L1-3.1.1, SC.L1-3.13.1
- SOC 2: CC6.1, CC6.6
- ISO 27001: 8.3, 8.20

**Remediation Action**

1. Storage account → Data management → Object replication → Advanced settings → uncheck "Allow cross-tenant replication".

**Links**
- [Prevent cross-tenant object replication](https://learn.microsoft.com/en-us/azure/storage/blobs/object-replication-prevent-cross-tenant-policies)

<!--- Results --->
%TestResult%
