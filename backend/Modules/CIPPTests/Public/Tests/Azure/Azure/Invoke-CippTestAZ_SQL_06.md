Private endpoints keep the server off the internet entirely. Where a public endpoint is required, AZ_SQL_02 covers its firewall.

**Remediation Action**

1. Create a private endpoint, move clients to it, then SQL server → Networking → Public network access = Disable.

**Links**
- [Azure SQL connectivity settings](https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings)

<!--- Results --->
%TestResult%
