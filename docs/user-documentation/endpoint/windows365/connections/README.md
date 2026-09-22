# Windows 365 — Network Connections

The Azure network connections a Windows 365 provisioning policy can join Cloud PCs through:
subscription, virtual network, subnet, region, and the connection's health check status.

## healthCheckStatus is the column that matters

A connection whose health check is not **passed** will fail provisioning. That is why it sits
immediately after the name rather than in the detail pane. Check it before pointing a new
provisioning policy at a connection, and check it first when provisioning fails for no obvious
reason.

## Hybrid join depends on these

Entra-only Cloud PCs can use a Microsoft-hosted network and need no connection here. Hybrid Entra
join must use one of these connections, and it needs line of sight to a domain controller.

## Read-only

Creating and editing network connections is done in the Intune portal — they involve Azure
subscription, vNet and domain-join credentials that live outside CIPP.
