import { Layout as DashboardLayout } from "../../../../layouts/index";
import CippFormPage from "../../../../components/CippFormPages/CippFormPage";
import CippFormComponent from "../../../../components/CippComponents/CippFormComponent";
import { CippFormCondition } from "../../../../components/CippComponents/CippFormCondition";
import { CippFormTenantSelector } from "../../../../components/CippComponents/CippFormTenantSelector";
import { useForm } from "react-hook-form";
import { Grid } from "@mui/system";

const Page = () => {
  const formControl = useForm({
    mode: "onChange",
    defaultValues: { PrinterType: "DirectIP", DriverSource: "Inbox" },
  });

  return (
    <CippFormPage
      title="Printer Catalogue Entry"
      formControl={formControl}
      queryKey="PrinterCatalog"
      backButtonTitle="Printer Catalogue"
      postUrl="/api/AddPrinterCatalogEntry"
    >
      <Grid container spacing={2}>
        <Grid size={{ xs: 12 }}>
          <CippFormTenantSelector formControl={formControl} name="tenantFilter" type="single" />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <CippFormComponent
            type="textField"
            label="Printer name"
            name="Name"
            formControl={formControl}
            validators={{ required: "A printer name is required" }}
          />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <CippFormComponent
            type="select"
            label="Printer type"
            name="PrinterType"
            formControl={formControl}
            options={[
              { label: "Universal Print", value: "UniversalPrint" },
              { label: "Direct IP", value: "DirectIP" },
              { label: "Print server share", value: "ServerShare" },
            ]}
            validators={{ required: "A printer type is required" }}
          />
        </Grid>

        <CippFormCondition
          formControl={formControl}
          field="PrinterType"
          compareType="is"
          compareValue="UniversalPrint"
        >
          <Grid size={{ xs: 12, md: 6 }}>
            <CippFormComponent
              type="textField"
              label="Universal Print share ID"
              name="ShareId"
              formControl={formControl}
              validators={{ required: "A Universal Print entry needs the share ID" }}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 6 }}>
            <CippFormComponent
              type="textField"
              label="Share name (optional, for display)"
              name="ShareName"
              formControl={formControl}
            />
          </Grid>
        </CippFormCondition>

        <CippFormCondition
          formControl={formControl}
          field="PrinterType"
          compareType="is"
          compareValue="DirectIP"
        >
          <Grid size={{ xs: 12, md: 4 }}>
            <CippFormComponent
              type="textField"
              label="Host address (IP or DNS name)"
              name="HostAddress"
              formControl={formControl}
              validators={{ required: "A direct IP printer needs a host address" }}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 2 }}>
            <CippFormComponent
              type="number"
              label="Port (default 9100)"
              name="PortNumber"
              formControl={formControl}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 6 }}>
            <CippFormComponent
              type="textField"
              label="Driver name (as it appears in the driver store)"
              name="DriverName"
              formControl={formControl}
              validators={{ required: "A direct IP printer needs a driver name" }}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 6 }}>
            <CippFormComponent
              type="select"
              label="Driver source"
              name="DriverSource"
              formControl={formControl}
              options={[
                { label: "Inbox driver (shipped with Windows)", value: "Inbox" },
                { label: "Staged by an Intune Win32 app", value: "Win32App" },
                { label: "Stage from an INF path (pnputil)", value: "InfPath" },
              ]}
            />
          </Grid>
          <CippFormCondition
            formControl={formControl}
            field="DriverSource"
            compareType="is"
            compareValue="InfPath"
          >
            <Grid size={{ xs: 12 }}>
              <CippFormComponent
                type="textField"
                label="Driver INF path on the device (e.g. C:\\Drivers\\hp\\hpcu255u.inf)"
                name="DriverInfPath"
                formControl={formControl}
                validators={{ required: "Staging from an INF needs the path to the .inf" }}
              />
            </Grid>
          </CippFormCondition>
        </CippFormCondition>

        <CippFormCondition
          formControl={formControl}
          field="PrinterType"
          compareType="is"
          compareValue="ServerShare"
        >
          <Grid size={{ xs: 12 }}>
            <CippFormComponent
              type="textField"
              label="UNC path (\\\\server\\queue) - deploys in the user context"
              name="UNCPath"
              formControl={formControl}
              validators={{ required: "A server share printer needs a UNC path" }}
            />
          </Grid>
        </CippFormCondition>

        <Grid size={{ xs: 12, md: 6 }}>
          <CippFormComponent
            type="textField"
            label="Location (optional)"
            name="Location"
            formControl={formControl}
          />
        </Grid>
        <Grid size={{ xs: 12, md: 6 }}>
          <CippFormComponent
            type="textField"
            label="Assign to group (optional, name or object id)"
            name="AssignTo"
            formControl={formControl}
          />
        </Grid>
        <Grid size={{ xs: 12 }}>
          <CippFormComponent
            type="textField"
            label="Comment (optional)"
            name="Comment"
            formControl={formControl}
          />
        </Grid>
      </Grid>
    </CippFormPage>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
