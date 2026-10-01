If allowed at the account level, any container can be made public by a single setting. That is a common cause of data leaks.

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

1. Storage account → Configuration → Allow Blob anonymous access = Disabled.
2. Check first that no website or app serves public files from a container.

**Links**
- [Prevent anonymous read access](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent)

<!--- Results --->
%TestResult%
