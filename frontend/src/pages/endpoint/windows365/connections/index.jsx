import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippTablePage } from "../../../../components/CippComponents/CippTablePage.jsx";
import { useSettings } from "../../../../hooks/use-settings";

// Azure network connections used by Windows 365 provisioning policies.
// healthCheckStatus sits right after the name on purpose: a connection that is not passing will
// fail provisioning, and that is the single most useful thing to see at a glance here.
const Page = () => {
  const tenant = useSettings().currentTenant;

  const simpleColumns = [
    "displayName",
    "healthCheckStatus",
    "connectionType",
    "virtualNetworkLocation",
    "subscriptionName",
    "adDomainName",
    "organizationalUnit",
  ];

  const offCanvas = {
    extendedInfoFields: [
      "displayName",
      "healthCheckStatus",
      "connectionType",
      "virtualNetworkId",
      "subnetId",
      "subscriptionId",
      "adDomainName",
      "organizationalUnit",
      "id",
    ],
  };

  return (
    <CippTablePage
      title="Windows 365 Network Connections"
      apiUrl="/api/ListCloudPCOnPremisesConnections"
      apiData={{ tenantFilter: tenant }}
      queryKey={`ListCloudPCOnPremisesConnections-${tenant}`}
      simpleColumns={simpleColumns}
      offCanvas={offCanvas}
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;
export default Page;
