An open storage firewall means a leaked key or SAS works from anywhere on the internet.

**Frameworks** (indicative)

- Themes: Restricting public and network access to data stores; Network boundary protection and exposure of services
- MCSB: NS-2, NS-1
- CIS Controls v8: 3.3, 4.4, 12.2
- NIST CSF 2.0: PR.DS, PR.AA, PR.IR
- NIST 800-53: AC-3, SC-7, CM-7
- CMMC / 800-171: AC.L1-3.1.1, SC.L1-3.13.1, CM.L2-3.4.7
- SOC 2: CC6.1, CC6.6
- ISO 27001: 8.3, 8.20, 8.22

**Remediation Action**

1. Storage account → Networking → "Enabled from selected virtual networks and IP addresses" (or Disabled + private endpoint).
2. Add the client's office IPs and required VNets.

**Links**
- [Storage firewalls and virtual networks](https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security)

<!--- Results --->
%TestResult%
