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

  // Lifecycle actions. The three destructive ones ask the operator to type the Cloud PC's exact
  // display name - the backend compares it against the name it fetches from Graph itself, so a
  // stale row here cannot satisfy it. There is no multi-select variant of these on purpose.
  const actions = [
    {
      label: "Resize",
      type: "POST",
      url: "/api/ExecCloudPCAction",
      data: { CloudPcId: "id", tenantFilter: `!${tenant}`, Action: "!resize", Confirm: true },
      confirmText:
        "Resize this Cloud PC. User data is retained, but the machine restarts and is unavailable while it happens.",
      fields: [
        {
          label: "Target Service Plan",
          name: "TargetServicePlanId",
          type: "select",
          multiple: false,
          creatable: false,
          required: true,
          api: {
            url: "/api/ListCloudPCGalleryImages",
            queryKey: `CloudPCServicePlans-${tenant}`,
            valueField: "id",
            labelField: "displayName",
          },
        },
      ],
    },
    {
      label: "Restore from Snapshot",
      type: "POST",
      url: "/api/ExecCloudPCAction",
      data: { CloudPcId: "id", tenantFilter: `!${tenant}`, Action: "!restore" },
      confirmText:
        "DESTRUCTIVE: restoring rolls this Cloud PC back to the selected snapshot. Everything written since that snapshot is lost. Type the Cloud PC's exact display name to confirm.",
      fields: [
        { label: "Snapshot ID (from the Intune portal)", name: "SnapshotId", type: "textField", required: true },
        { label: "Type the Cloud PC display name to confirm", name: "ConfirmText", type: "textField", required: true },
      ],
    },
    {
      label: "Reprovision",
      type: "POST",
      url: "/api/ExecCloudPCAction",
      data: { CloudPcId: "id", tenantFilter: `!${tenant}`, Action: "!reprovision" },
      confirmText:
        "DESTRUCTIVE: reprovisioning rebuilds this Cloud PC from its policy image and WIPES THE LOCAL DISK. Anything not in OneDrive, a roaming profile or the mailbox is gone. Type the Cloud PC's exact display name to confirm.",
      fields: [
        { label: "Type the Cloud PC display name to confirm", name: "ConfirmText", type: "textField", required: true },
      ],
    },
    {
      label: "End Grace Period (deprovision)",
      type: "POST",
      url: "/api/ExecCloudPCAction",
      data: { CloudPcId: "id", tenantFilter: `!${tenant}`, Action: "!endGracePeriod" },
      confirmText:
        "DESTRUCTIVE: this ends the grace period immediately and DEPROVISIONS the Cloud PC. It is a deletion, not a pause. Type the Cloud PC's exact display name to confirm.",
      fields: [
        { label: "Type the Cloud PC display name to confirm", name: "ConfirmText", type: "textField", required: true },
      ],
    },
    {
      label: "Troubleshoot",
      type: "POST",
      url: "/api/ExecCloudPCAction",
      data: { CloudPcId: "id", tenantFilter: `!${tenant}`, Action: "!troubleshoot" },
      confirmText: "Run Microsoft's health checks against this Cloud PC. Changes nothing.",
    },
  ];

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
    actions: actions,
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
        actions={actions}
        simpleColumns={simpleColumns}
        offCanvas={offCanvas}
      />
    </Stack>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;
export default Page;
