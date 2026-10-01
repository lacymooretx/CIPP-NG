Standing Owner access means a phished admin session is immediately a subscription takeover. With Privileged Identity Management, admins hold the role as eligible and activate it, with MFA and justification, only when needed.

**Frameworks** (indicative)

- Themes: No standing privileged access
- MCSB: PA-2
- CIS Controls v8: 5.4
- NIST CSF 2.0: PR.AA
- NIST 800-53: AC-6
- CMMC / 800-171: AC.L2-3.1.5, AC.L2-3.1.6
- SOC 2: CC6.3
- ISO 27001: 8.2

**Remediation Action**

1. Requires Microsoft Entra ID P2 (or Entra ID Governance).
2. In PIM → Azure resources, convert the listed assignments from Active to Eligible.
3. Keep one break-glass account with permanent access, excluded from Conditional Access lockouts.

**Links**
- [Assign Azure resource roles in PIM](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-assign-roles)

<!--- Results --->
%TestResult%
