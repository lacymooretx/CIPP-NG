Vault access policies sit outside Azure RBAC: they are not covered by PIM, role reviews or deny assignments, and anyone with Contributor can edit them.

**Frameworks** (indicative)

- Themes: Protection of keys and secrets; Least privilege for administrative roles
- MCSB: DP-8, PA-1, PA-7
- CIS Controls v8: 5.4, 6.8
- NIST CSF 2.0: PR.DS, PR.AA
- NIST 800-53: SC-12, AC-6, AC-6(5)
- CMMC / 800-171: SC.L2-3.13.10, AC.L2-3.1.5
- SOC 2: CC6.1, CC6.3
- ISO 27001: 8.24, 8.2

**Remediation Action**

1. Map existing access policies to Key Vault RBAC roles, then Access configuration → Azure role-based access control.

**Links**
- [Migrate to Azure RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-migration)

<!--- Results --->
%TestResult%
