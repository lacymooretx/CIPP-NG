Flow logs record which IPs talked to what. They are essential for investigating lateral movement and data exfiltration. (NSG flow logs are being retired; VNet flow logs replace them.)

**Remediation Action**

1. Network Watcher → Flow logs → Create → target the virtual network → send to a storage account (and Traffic Analytics if wanted).

**Links**
- [VNet flow logs](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview)

<!--- Results --->
%TestResult%
