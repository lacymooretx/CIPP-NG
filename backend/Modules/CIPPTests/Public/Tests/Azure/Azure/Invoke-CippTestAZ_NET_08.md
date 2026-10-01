A public IP puts the VM directly on the internet, protected only by its NSG. Web servers may need this; most VMs do not.

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

1. Remove the public IP from the NIC; publish services through a load balancer, application gateway or Front Door, and administer via Bastion.

**Links**
- [Azure Bastion](https://learn.microsoft.com/en-us/azure/bastion/bastion-overview)

<!--- Results --->
%TestResult%
