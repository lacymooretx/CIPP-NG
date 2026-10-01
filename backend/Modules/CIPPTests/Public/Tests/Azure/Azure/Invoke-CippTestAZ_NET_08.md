A public IP puts the VM directly on the internet, protected only by its NSG. Web servers may need this; most VMs do not.

**Remediation Action**

1. Remove the public IP from the NIC; publish services through a load balancer, application gateway or Front Door, and administer via Bastion.

**Links**
- [Azure Bastion](https://learn.microsoft.com/en-us/azure/bastion/bastion-overview)

<!--- Results --->
%TestResult%
