import React from "react";
import { Alert, Typography } from "@mui/material";
import { Grid } from "@mui/system";
import { useForm } from "react-hook-form";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import CippFormPage from "../../../../components/CippFormPages/CippFormPage";
import CippFormComponent from "../../../../components/CippComponents/CippFormComponent";
import { CippFormCondition } from "../../../../components/CippComponents/CippFormCondition";
import { useSettings } from "../../../../hooks/use-settings";

// Create a Windows 365 provisioning policy.
//
// Creating the policy builds nothing. A Cloud PC is only created once the policy is assigned to a
// group whose members hold Windows 365 licences, which is a separate action on the policy list.
// That separation is deliberate and the banner says so, because "save" on a form that silently
// starts building machines for people - and consuming licences - is not a good surprise.
const AddProvisioningPolicyForm = () => {
  const tenant = useSettings().currentTenant;

  const formControl = useForm({
    mode: "onChange",
    defaultValues: {
      tenantFilter: tenant,
      ProvisioningType: "dedicated",
      DomainJoinType: "azureADJoin",
      EnableSingleSignOn: true,
      Locale: "en-US",
      CloudPcNamingTemplate: "CPC-%USERNAME:5%-%RAND:5%",
    },
  });

  return (
    <CippFormPage
      title="Add Windows 365 Provisioning Policy"
      formControl={formControl}
      queryKey={`ListCloudPCProvisioningPolicies-${tenant}`}
      backButtonTitle="Provisioning Policies"
      postUrl="/api/AddCloudPCProvisioningPolicy"
    >
      <Typography variant="h6" sx={{ mb: 2 }}>
        Add Provisioning Policy
      </Typography>

      <Alert severity="info" sx={{ mb: 2 }}>
        Creating this policy does not provision anything and consumes no licences. Cloud PCs are
        only built once you assign the policy to a group, from the Provisioning Policies list.
      </Alert>

      <Grid container spacing={2}>
        <Grid size={{ xs: 12 }}>
          <CippFormComponent
            type="textField"
            label="Policy Name"
            name="DisplayName"
            formControl={formControl}
            validators={{ required: "A policy name is required" }}
          />
        </Grid>

        <Grid size={{ xs: 12 }}>
          <CippFormComponent
            type="textField"
            label="Description"
            name="Description"
            formControl={formControl}
          />
        </Grid>

        <Grid size={{ xs: 12 }}>
          <CippFormComponent
            type="autoComplete"
            label="Image"
            name="ImageId"
            multiple={false}
            creatable={false}
            formControl={formControl}
            validators={{ required: "An image is required" }}
            api={{
              url: "/api/ListCloudPCGalleryImages",
              queryKey: `ListCloudPCGalleryImages-${tenant}`,
              labelField: "displayName",
              valueField: "id",
            }}
          />
        </Grid>

        <Grid size={{ xs: 12 }}>
          <CippFormComponent
            type="radio"
            label="Provisioning Type"
            name="ProvisioningType"
            row
            options={[
              { label: "Dedicated (one Cloud PC per user)", value: "dedicated" },
              { label: "Shared / Frontline", value: "shared" },
            ]}
            formControl={formControl}
          />
        </Grid>

        <Grid size={{ xs: 12 }}>
          <CippFormComponent
            type="radio"
            label="Join Type"
            name="DomainJoinType"
            row
            options={[
              { label: "Microsoft Entra join", value: "azureADJoin" },
              { label: "Hybrid Entra join", value: "hybridAzureADJoin" },
            ]}
            formControl={formControl}
          />
        </Grid>

        {/* Hybrid join cannot use a Microsoft-hosted network - it has to reach a domain
            controller, so it requires one of your own network connections. */}
        <CippFormCondition
          formControl={formControl}
          field="DomainJoinType"
          compareType="is"
          compareValue="hybridAzureADJoin"
        >
          <Grid size={{ xs: 12 }}>
            <Alert severity="warning" sx={{ mb: 1 }}>
              Hybrid join requires one of your own Azure network connections with line of sight to a
              domain controller. Provisioning fails if the connection&apos;s health check is not
              passing.
            </Alert>
            <CippFormComponent
              type="autoComplete"
              label="On-premises Network Connection"
              name="OnPremisesConnectionId"
              multiple={false}
              creatable={false}
              formControl={formControl}
              validators={{ required: "Hybrid join requires a network connection" }}
              api={{
                url: "/api/ListCloudPCOnPremisesConnections",
                queryKey: `ListCloudPCOnPremisesConnections-${tenant}`,
                labelField: "displayName",
                valueField: "id",
              }}
            />
          </Grid>
        </CippFormCondition>

        <CippFormCondition
          formControl={formControl}
          field="DomainJoinType"
          compareType="is"
          compareValue="azureADJoin"
        >
          <Grid size={{ xs: 12 }}>
            <CippFormComponent
              type="textField"
              label="Region (Microsoft-hosted network, e.g. centralus)"
              name="RegionName"
              formControl={formControl}
              validators={{ required: "Entra join requires a region" }}
            />
          </Grid>
        </CippFormCondition>

        <Grid size={{ xs: 12 }}>
          <CippFormComponent
            type="textField"
            label="Cloud PC Naming Template"
            name="CloudPcNamingTemplate"
            formControl={formControl}
          />
        </Grid>

        <Grid size={{ xs: 12 }}>
          <CippFormComponent
            type="switch"
            label="Enable single sign-on"
            name="EnableSingleSignOn"
            formControl={formControl}
          />
        </Grid>

        <Grid size={{ xs: 12 }}>
          <CippFormComponent
            type="textField"
            label="Locale"
            name="Locale"
            formControl={formControl}
          />
        </Grid>
      </Grid>
    </CippFormPage>
  );
};

AddProvisioningPolicyForm.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;
export default AddProvisioningPolicyForm;
