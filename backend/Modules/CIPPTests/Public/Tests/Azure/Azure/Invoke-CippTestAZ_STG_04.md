An open storage firewall means a leaked key or SAS works from anywhere on the internet.

**Remediation Action**

1. Storage account → Networking → "Enabled from selected virtual networks and IP addresses" (or Disabled + private endpoint).
2. Add the client's office IPs and required VNets.

**Links**
- [Storage firewalls and virtual networks](https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security)

<!--- Results --->
%TestResult%
