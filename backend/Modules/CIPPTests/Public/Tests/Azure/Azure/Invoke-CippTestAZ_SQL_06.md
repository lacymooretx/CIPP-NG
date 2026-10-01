Private endpoints keep the server off the internet entirely. Where a public endpoint is required, AZ_SQL_02 covers its firewall.

**Frameworks** (indicative)

- Themes: Network boundary protection and exposure of services; Restricting public and network access to data stores
- MCSB: NS-1, NS-2
- CIS Controls v8: 4.4, 12.2, 3.3
- NIST CSF 2.0: PR.IR, PR.DS, PR.AA
- NIST 800-53: SC-7, CM-7, AC-3
- CMMC / 800-171: SC.L1-3.13.1, CM.L2-3.4.7, AC.L1-3.1.1
- SOC 2: CC6.6, CC6.1
- ISO 27001: 8.20, 8.22, 8.3

**Remediation Action**

1. Create a private endpoint, move clients to it, then SQL server → Networking → Public network access = Disable.

**Links**
- [Azure SQL connectivity settings](https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings)

<!--- Results --->
%TestResult%
