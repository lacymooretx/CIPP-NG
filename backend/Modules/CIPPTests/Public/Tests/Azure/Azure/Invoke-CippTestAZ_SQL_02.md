A 0.0.0.0–255.255.255.255 rule exposes the server to every brute-force bot. "Allow Azure services" admits any Azure customer's resources, not just the client's own.

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

1. Replace with specific client IPs, VNet rules or a private endpoint.

**Links**
- [Azure SQL firewall rules](https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure)

<!--- Results --->
%TestResult%
