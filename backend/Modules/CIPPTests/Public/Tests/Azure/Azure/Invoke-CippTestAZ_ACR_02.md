Anonymous pull exposes every image, and any secrets baked into it, to the internet.

**Remediation Action**

1. `az acr update --name <registry> --anonymous-pull-enabled false`.

**Links**
- [Registry authentication](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication)

<!--- Results --->
%TestResult%
