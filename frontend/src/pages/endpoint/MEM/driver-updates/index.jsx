// Windows driver and firmware update review queue (Aspendora fork, Vikunja CIPP-24).
// Reads /api/ListDriverUpdateQueue (one tenant or AllTenants). Approve / Decline / Suspend post to
// /api/ExecDriverUpdateAction, which changes the tenant: approved drivers start installing.
import { useState } from "react";
import { Alert, Button, Container, Grid, ToggleButton, ToggleButtonGroup, Typography } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import CippTablePage from "../../../../components/CippComponents/CippTablePage";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { ApiGetCall } from "../../../../api/ApiCall";
import { useSettings } from "../../../../hooks/use-settings";

const simpleColumns = [
  "Tenant",
  "Name",
  "Manufacturer",
  "DriverClass",
  "Version",
  "ApplicableDeviceCount",
  "ApprovalStatus",
  "ProfileName",
  "ApprovalType",
  "ReleaseDate",
];

const driverAction = (label, action, icon, color, confirmText) => ({
  label,
  type: "POST",
  url: "/api/ExecDriverUpdateAction",
  data: { ProfileId: "ProfileId", DriverIds: "DriverId", Action: `!${action}` },
  confirmText,
  icon,
  color,
  multiPost: false,
});

const actions = [
  driverAction(
    "Approve",
    "Approve",
    <CippIcons.Check />,
    "success",
    'Approve "[Name]" in "[ProfileName]" ([Tenant])? It starts installing now on the [ApplicableDeviceCount] applicable device(s) in the profile\'s groups.'
  ),
  driverAction(
    "Decline",
    "Decline",
    <CippIcons.Block />,
    "warning",
    'Decline "[Name]" in "[ProfileName]" ([Tenant])? It will not be offered to devices in this profile.'
  ),
  driverAction(
    "Suspend",
    "Suspend",
    <CippIcons.Pause />,
    "warning",
    'Suspend "[Name]" in "[ProfileName]" ([Tenant])? Devices that have not installed it yet stop receiving it.'
  ),
];

const Page = () => {
  const tenant = useSettings().currentTenant;
  const [status, setStatus] = useState("needsReview");
  const queryKey = `ListDriverUpdateQueue-${tenant}-${status}`;
  const report = ApiGetCall({
    url: "/api/ListDriverUpdateQueue",
    data: { tenantFilter: tenant, Status: status },
    queryKey,
    waiting: Boolean(tenant),
  });

  const data = report.data ?? {};
  const drivers = Array.isArray(data.Results) ? data.Results : [];
  const tenants = Array.isArray(data.Tenants) ? data.Tenants : [];
  const failed = Array.isArray(data.Failed) ? data.Failed : [];
  const skipped = Array.isArray(data.Skipped) ? data.Skipped : [];
  const unavailable = tenants.filter((t) => t?.Available === false);
  const withErrors = tenants.filter((t) => t?.Available !== false && (t?.Errors ?? []).length > 0);
  const devices = drivers.reduce((sum, d) => sum + (Number(d?.ApplicableDeviceCount) || 0), 0);

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {report.isError && (
          <Grid size={12}>
            <Alert severity="error">
              {report.error?.response?.data?.Results ?? "The driver queue could not be read."}
            </Alert>
          </Grid>
        )}
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              { icon: <CippIcons.Update />, data: drivers.length, name: status === "needsReview" ? "Drivers awaiting review" : "Drivers", color: "warning" },
              { icon: <CippIcons.Memory />, data: devices, name: "Applicable devices (sum)", color: "info" },
              { icon: <CippIcons.FactCheck />, data: tenants.filter((t) => t?.Available !== false).length, name: "Tenants with driver management", color: "secondary" },
              { icon: <CippIcons.Warning />, data: unavailable.length, name: "Tenants without driver management", color: "error" },
            ]}
          />
        </Grid>
        {unavailable.length > 0 && (
          <Grid size={12}>
            <Alert severity="info">
              Driver update management is unavailable in {unavailable.map((t) => t.Tenant).join(", ")}. It needs
              Windows Enterprise E3/E5 or Microsoft 365 Business Premium rights and devices onboarded to the Windows
              Update for Business deployment service (Autopatch).
            </Alert>
          </Grid>
        )}
        {(withErrors.length > 0 || failed.length > 0 || skipped.length > 0) && (
          <Grid size={12}>
            <Typography color="error" variant="body2">
              {[
                ...withErrors.map((t) => `${t.Tenant}: ${(t.Errors ?? []).join("; ")}`),
                ...failed.map((f) => `${f.Tenant}: ${f.Error}`),
                skipped.length > 0 ? `Not reached in time: ${skipped.join(", ")}` : null,
              ]
                .filter(Boolean)
                .join(" | ")}
            </Typography>
          </Grid>
        )}
        <Grid size={12}>
          <CippTablePage
            title="Driver Update Review Queue"
            tenantInTitle={true}
            data={drivers}
            isFetching={report.isFetching}
            // Rows come from the report query above; the table only needs its own cache key.
            queryKey={`${queryKey}-table`}
            actions={actions}
            offCanvas={{
              extendedInfoFields: [...simpleColumns, "Category", "DeployDate", "Autopatch", "ProfileId", "DriverId"],
              actions,
            }}
            simpleColumns={simpleColumns}
            maxHeightOffset="420px"
            cardButton={
              <>
                <ToggleButtonGroup
                  size="small"
                  exclusive
                  value={status}
                  onChange={(_, value) => value && setStatus(value)}
                  sx={{ mr: 1 }}
                >
                  <ToggleButton value="needsReview">Needs review</ToggleButton>
                  <ToggleButton value="all">All</ToggleButton>
                </ToggleButtonGroup>
                <Button
                  startIcon={<CippIcons.Refresh />}
                  disabled={report.isFetching}
                  onClick={() => report.refetch()}
                >
                  {report.isFetching ? "Loading..." : "Refresh"}
                </Button>
              </>
            }
          />
        </Grid>
      </Grid>
    </Container>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
