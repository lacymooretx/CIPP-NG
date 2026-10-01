Account keys never expire and grant full access. Disabling them forces Entra ID authentication. Many tools still need keys, so this is flagged for review rather than failed.

**Remediation Action**

1. Confirm nothing uses the account keys or account-key SAS, then Configuration → Allow storage account key access = Disabled.

**Links**
- [Prevent Shared Key authorization](https://learn.microsoft.com/en-us/azure/storage/common/shared-key-authorization-prevent)

<!--- Results --->
%TestResult%
