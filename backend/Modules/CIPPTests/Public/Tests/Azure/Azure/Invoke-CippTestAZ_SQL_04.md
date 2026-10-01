SQL logins are passwords without MFA. Entra-only authentication removes them. Many line-of-business apps still need a SQL login, so this is flagged for review.

**Remediation Action**

1. After apps move to managed identity or Entra logins: SQL server → Microsoft Entra ID → "Support only Microsoft Entra authentication".

**Links**
- [Entra-only authentication](https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-azure-ad-only-authentication)

<!--- Results --->
%TestResult%
