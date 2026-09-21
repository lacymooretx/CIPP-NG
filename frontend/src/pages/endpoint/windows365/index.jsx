import { Alert, AlertTitle, Stack } from "@mui/material";
import { Layout as DashboardLayout } from "../../../layouts/index";
import { CippTablePage } from "../../../components/CippComponents/CippTablePage.jsx";
import { ApiGetCall } from "../../../api/ApiCall";
import { useSettings } from "../../../hooks/use-settings";

// Windows 365 Cloud PC inventory.
//
// The banner below is the point of this page as much as the table is. The Cloud PC API answers
// "this tenant has no Windows 365 licence" with the same access-denied error it uses for a real
// permission fault, so a bare empty table here would send whoever is looking at it off to check
// consent that is already correct. The backend classifies which of the two it is and returns
// cloudPcState; we surface that verbatim rather than guessing in the UI.
const Page = () => {
  const pageTitle = "Windows 365 Cloud PCs";
  const tenant = useSettings().currentTenant;

  const cloudPcs = ApiGetCall({
    url: "/api/ListCloudPCs",
    data: { tenantFilter: tenant },
    queryKey: `ListCloudPCs-${tenant}`,
  });

  const rows = Array.isArray(cloudPcs.data) ? cloudPcs.data : [];
  const state = rows.find((r) => r?.cloudPcState && r.cloudPcState !== "Ok");

  const banner = state ? (
    <Alert severity={state.cloudPcState === "NotLicensed" ? "info" : "warning"} sx={{ mb: 2 }}>
      <AlertTitle>
        {state.cloudPcState === "NotLicensed"
          ? "No Windows 365 licence in this tenant"
          : "Cloud PC data unavailable"}
      </AlertTitle>
      {state.cloudPcStateMessage}
    </Alert>
  ) : null;

  const simpleColumns = [
    "displayName",
    "userPrincipalName",
    "status",
    "servicePlanName",
    "provisioningPolicyName",
    "imageDisplayName",
    "managedDeviceName",
    "diskEncryptionState",
    "provisioningType",
    "gracePeriodEndDateTime",
    "lastModifiedDateTime",
  ];

  const offCanvas = {
    extendedInfoFields: [
      "displayName",
      "userPrincipalName",
      "servicePlanName",
      "provisioningPolicyName",
      "imageDisplayName",
      "status",
      "diskEncryptionState",
      "gracePeriodEndDateTime",
      "managedDeviceId",
      "aadDeviceId",
      "id",
    ],
  };

  return (
    <Stack>
      {banner}
      <CippTablePage
        title={pageTitle}
        apiUrl="/api/ListCloudPCs"
        apiData={{ tenantFilter: tenant }}
        queryKey={`ListCloudPCs-${tenant}`}
        simpleColumns={simpleColumns}
        offCanvas={offCanvas}
      />
    </Stack>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;
export default Page;
