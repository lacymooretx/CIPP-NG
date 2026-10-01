Unmanaged disks live as VHD blobs in a storage account, inheriting its keys and network exposure. They are retired and lose platform protections.

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

1. Convert the VM to managed disks (requires a stop/deallocate).

**Links**
- [Migrate to managed disks](https://learn.microsoft.com/en-us/azure/virtual-machines/windows/convert-unmanaged-to-managed-disks)

<!--- Results --->
%TestResult%
