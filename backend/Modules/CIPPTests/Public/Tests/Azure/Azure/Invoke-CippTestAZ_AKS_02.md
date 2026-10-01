An open Kubernetes API server is directly attackable with any leaked kubeconfig.

**Frameworks** (indicative)

- Themes: Network boundary protection and exposure of services
- MCSB: NS-1, NS-2
- CIS Controls v8: 4.4, 12.2
- NIST CSF 2.0: PR.IR
- NIST 800-53: SC-7, CM-7
- CMMC / 800-171: SC.L1-3.13.1, CM.L2-3.4.7
- SOC 2: CC6.6
- ISO 27001: 8.20, 8.22

**Remediation Action**

1. Set API server authorised IP ranges, or make the cluster private.

**Links**
- [API server authorized IP ranges](https://learn.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges)

<!--- Results --->
%TestResult%
