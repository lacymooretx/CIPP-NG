Flow logs record which IPs talked to what. They are essential for investigating lateral movement and data exfiltration. (NSG flow logs are being retired; VNet flow logs replace them.)

**Frameworks** (indicative)

- Themes: Network traffic logging
- MCSB: LT-4
- CIS Controls v8: 13.6
- NIST CSF 2.0: DE.CM
- NIST 800-53: AU-12, SI-4
- CMMC / 800-171: AU.L2-3.3.1
- SOC 2: CC7.2
- ISO 27001: 8.16

**Remediation Action**

1. Network Watcher → Flow logs → Create → target the virtual network → send to a storage account (and Traffic Analytics if wanted).

**Links**
- [VNet flow logs](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview)

<!--- Results --->
%TestResult%
