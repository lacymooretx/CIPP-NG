An open key vault firewall lets a stolen token read secrets from anywhere.

**Frameworks** (indicative)

- Themes: Protection of keys and secrets; Network boundary protection and exposure of services
- MCSB: DP-8, NS-1, NS-2
- CIS Controls v8: 4.4, 12.2
- NIST CSF 2.0: PR.DS, PR.IR
- NIST 800-53: SC-12, SC-7, CM-7
- CMMC / 800-171: SC.L2-3.13.10, SC.L1-3.13.1, CM.L2-3.4.7
- SOC 2: CC6.1, CC6.6
- ISO 27001: 8.24, 8.20, 8.22

**Remediation Action**

1. Key vault → Networking → "Allow public access from specific virtual networks and IP addresses" or Disable public access + private endpoint.

**Links**
- [Key Vault network security](https://learn.microsoft.com/en-us/azure/key-vault/general/network-security)

<!--- Results --->
%TestResult%
