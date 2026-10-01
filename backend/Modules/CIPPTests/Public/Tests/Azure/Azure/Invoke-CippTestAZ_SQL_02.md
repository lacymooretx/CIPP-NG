A 0.0.0.0–255.255.255.255 rule exposes the server to every brute-force bot. "Allow Azure services" admits any Azure customer's resources, not just the client's own.

**Remediation Action**

1. Replace with specific client IPs, VNet rules or a private endpoint.

**Links**
- [Azure SQL firewall rules](https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure)

<!--- Results --->
%TestResult%
