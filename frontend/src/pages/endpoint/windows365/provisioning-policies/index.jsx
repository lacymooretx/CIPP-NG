import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippTablePage } from "../../../../components/CippComponents/CippTablePage.jsx";
import { Button } from "@mui/material";
import { Add } from "@mui/icons-material";
import Link from "next/link";
import { useSettings } from "../../../../hooks/use-settings";

// Windows 365 provisioning policies - the templates Cloud PCs get created from.
//
// The assign action defaults to AssignmentMode "Add" and the form says why: Graph's assign call is
// replace-mode, so sending one group to a policy that already serves five detaches the other four.
// Replace is offered, but it is a deliberate choice rather than the path of least resistance.
const Page = () => {
  const tenant = useSettings().currentTenant;

  const actions = [
    {
      label: "Assign to Groups",
      type: "POST",
      url: "/api/ExecCloudPCProvisioningPolicyAssign",
      data: { PolicyId: "id", tenantFilter: `!${tenant}` },
      confirmText:
        "Assign this provisioning policy to the selected group(s). Members holding a Windows 365 licence will have a Cloud PC provisioned.",
      fields: [
        {
          label: "Groups",
          name: "GroupIds",
          type: "select",
          multiple: true,
          creatable: false,
          required: true,
          api: {
            url: "/api/ListGroups",
            queryKey: `ListGroups-${tenant}`,
            valueField: "id",
            labelField: "displayName",
          },
        },
        {
          label: "Assignment Mode",
          name: "AssignmentMode",
          type: "select",
          multiple: false,
          creatable: false,
          options: [
            { label: "Add to existing assignments (recommended)", value: "Add" },
            { label: "Replace all assignments - detaches every group not listed above", value: "Replace" },
          ],
        },
      ],
    },
  ];

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
    actions: actions,
  };

  return (
    <CippTablePage
      title="Windows 365 Provisioning Policies"
      apiUrl="/api/ListCloudPCProvisioningPolicies"
      apiData={{ tenantFilter: tenant }}
      queryKey={`ListCloudPCProvisioningPolicies-${tenant}`}
      actions={actions}
      simpleColumns={simpleColumns}
      offCanvas={offCanvas}
      cardButton={
        <Button
          component={Link}
          href="/endpoint/windows365/provisioning-policies/add"
          startIcon={<Add />}
        >
          Add Policy
        </Button>
      }
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;
export default Page;
