Trusted Launch adds Secure Boot, vTPM and boot integrity monitoring, which defend against bootkits and rootkits.

**Frameworks** (indicative)

- Themes: Secure configuration of compute and platform services
- MCSB: PV-1, PV-3
- CIS Controls v8: 4.1
- NIST CSF 2.0: PR.PS
- NIST 800-53: CM-6, CM-7
- CMMC / 800-171: CM.L2-3.4.2, CM.L2-3.4.7
- SOC 2: CC7.1
- ISO 27001: 8.9

**Remediation Action**

1. New VMs: choose Trusted Launch (the default for Gen2 images).
2. Existing Gen2 VMs can be upgraded in place; Gen1 VMs must be converted first.

**Links**
- [Trusted launch](https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch)

<!--- Results --->
%TestResult%
