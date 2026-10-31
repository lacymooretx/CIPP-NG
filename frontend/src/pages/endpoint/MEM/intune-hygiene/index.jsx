// Intune policy assignment hygiene (Aspendora fork, Vikunja CIPP-19).
// Read-only report from /api/ListIntunePolicyHygiene: unassigned policies, exclusion-only
// policies, and assignments to groups that no longer exist or have no members.
import { Alert, Button, Container, Grid, Typography } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import CippTablePage from "../../../../components/CippComponents/CippTablePage";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { ApiGetCall } from "../../../../api/ApiCall";
import { useSettings } from "../../../../hooks/use-settings";

const simpleColumns = ["Severity", "Category", "PolicyType", "PolicyName", "Group", "Message"];

const filters = [
  { filterName: "Unassigned", value: [{ id: "Category", value: "Unassigned" }], type: "column" },
  { filterName: "Exclusion only", value: [{ id: "Category", value: "ExclusionOnly" }], type: "column" },
  { filterName: "Missing group", value: [{ id: "Category", value: "MissingGroup" }], type: "column" },
  { filterName: "Empty group", value: [{ id: "Category", value: "EmptyGroup" }], type: "column" },
];

const Page = () => {
  const tenant = useSettings().currentTenant;
  const singleTenant = Boolean(tenant) && tenant !== "AllTenants";
  const queryKey = `ListIntunePolicyHygiene-${tenant}`;
  const report = ApiGetCall({
    url: "/api/ListIntunePolicyHygiene",
    data: { tenantFilter: tenant },
    queryKey,
    waiting: singleTenant,
  });

  const data = report.data ?? {};
  const findings = Array.isArray(data.Findings) ? data.Findings : [];
  const summary = data.Summary ?? {};
  const byCategory = summary.ByCategory ?? {};
  const errors = Array.isArray(data.Errors) ? data.Errors : [];
  const types = summary.PolicyTypes ?? {};

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {!singleTenant && (
          <Grid size={12}>
            <Alert severity="info">Select a single tenant to run the Intune hygiene report.</Alert>
          </Grid>
        )}
        {report.isError && (
          <Grid size={12}>
            <Alert severity="error">
              {report.error?.response?.data?.Results ?? "The report failed."}
            </Alert>
          </Grid>
        )}
        {singleTenant && (
          <>
            <Grid size={12}>
              <CippInfoBar
                isFetching={report.isFetching}
                data={[
                  { icon: <CippIcons.Policy />, data: summary.PoliciesChecked ?? 0, name: "Policies checked", color: "secondary" },
                  { icon: <CippIcons.Info />, data: byCategory.Unassigned ?? 0, name: "Unassigned", color: "info" },
                  { icon: <CippIcons.Warning />, data: byCategory.ExclusionOnly ?? 0, name: "Exclusion only", color: "warning" },
                  { icon: <CippIcons.Error />, data: byCategory.MissingGroup ?? 0, name: "Missing group", color: "error" },
                  { icon: <CippIcons.Warning />, data: byCategory.EmptyGroup ?? 0, name: "Empty group", color: "warning" },
                ]}
              />
            </Grid>
            {Object.keys(types).length > 0 && (
              <Grid size={12}>
                <Typography variant="body2" color="text.secondary">
                  {Object.entries(types)
                    .map(([name, t]) => `${name}: ${t?.Unassigned ?? 0} of ${t?.Total ?? 0} unassigned`)
                    .join(" | ")}
                </Typography>
              </Grid>
            )}
            {errors.length > 0 && (
              <Grid size={12}>
                <Typography color="error" variant="body2">
                  Not everything could be read: {errors.join("; ")}
                </Typography>
              </Grid>
            )}
            <Grid size={12}>
              <CippTablePage
                title="Intune Policy Hygiene"
                tenantInTitle={true}
                data={findings}
                isFetching={report.isFetching}
                // Rows come from the report query above; the table only needs its own cache key.
                queryKey={`${queryKey}-table`}
                offCanvas={{ extendedInfoFields: [...simpleColumns, "PolicyId", "Family", "Key"] }}
                simpleColumns={simpleColumns}
                filters={filters}
                maxHeightOffset="480px"
                cardButton={
                  <Button
                    startIcon={<CippIcons.Refresh />}
                    disabled={report.isFetching}
                    onClick={() => report.refetch()}
                  >
                    {report.isFetching ? "Checking..." : "Refresh"}
                  </Button>
                }
              />
            </Grid>
          </>
        )}
      </Grid>
    </Container>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
