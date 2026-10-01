TLS 1.0 and 1.1 have known weaknesses and are being retired across Azure.

**Frameworks** (indicative)

- Themes: Encryption of data in transit
- MCSB: DP-3
- CIS Controls v8: 3.10
- NIST CSF 2.0: PR.DS
- NIST 800-53: SC-8
- CMMC / 800-171: SC.L2-3.13.8
- SOC 2: CC6.7
- ISO 27001: 8.24

**Remediation Action**

1. Check client compatibility, then Storage account → Configuration → Minimum TLS version = 1.2.

**Links**
- [Enforce a minimum TLS version](https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version)

<!--- Results --->
%TestResult%
