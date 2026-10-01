If allowed at the account level, any container can be made public by a single setting. That is a common cause of data leaks.

**Remediation Action**

1. Storage account → Configuration → Allow Blob anonymous access = Disabled.
2. Check first that no website or app serves public files from a container.

**Links**
- [Prevent anonymous read access](https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent)

<!--- Results --->
%TestResult%
