Plain FTP sends deployment credentials unencrypted.

**Frameworks** (indicative)

- Themes: Encryption of data in transit; Secure configuration of compute and platform services
- MCSB: DP-3, PV-1, PV-3
- CIS Controls v8: 3.10, 4.1
- NIST CSF 2.0: PR.DS, PR.PS
- NIST 800-53: SC-8, CM-6, CM-7
- CMMC / 800-171: SC.L2-3.13.8, CM.L2-3.4.2, CM.L2-3.4.7
- SOC 2: CC6.7, CC7.1
- ISO 27001: 8.24, 8.9

**Remediation Action**

1. App → Configuration → General settings → FTP state = Disabled (or FTPS only).

**Links**
- [Deploy with FTP/S](https://learn.microsoft.com/en-us/azure/app-service/deploy-ftp)

<!--- Results --->
%TestResult%
