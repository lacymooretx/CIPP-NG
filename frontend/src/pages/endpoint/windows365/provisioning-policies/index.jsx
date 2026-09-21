import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippTablePage } from "../../../../components/CippComponents/CippTablePage.jsx";
import { useSettings } from "../../../../hooks/use-settings";

// Windows 365 provisioning policies - the templates Cloud PCs get created from.
// Read-only in this phase; creating and editing them is Phase 2 of the build.
const Page = () => {
  const pageTitle = "Windows 365 Provisioning Policies";
  const tenant = useSettings().currentTenant;

  const simpleColumns = [
    "displayName",
    "imageDisplayName",
    "imageType",
    "provisioningType",
    "domainJoinType",
    "cloudPcNamingTemplate",
    "enableSingleSignOn",
    "managedBy",
    "lastModifiedDateTime",
  ];

  const offCanvas = {
    extendedInfoFields: [
      "displayName",
      "description",
      "imageDisplayName",
      "provisioningType",
      "domainJoinType",
      "onPremisesConnectionId",
      "regionName",
      "cloudPcNamingTemplate",
      "id",
    ],
  };

  return (
    <CippTablePage
      title={pageTitle}
      apiUrl="/api/ListCloudPCProvisioningPolicies"
      apiData={{ tenantFilter: tenant }}
      queryKey={`ListCloudPCProvisioningPolicies-${tenant}`}
      simpleColumns={simpleColumns}
      offCanvas={offCanvas}
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;
export default Page;
