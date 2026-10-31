// Break-glass posture for the selected tenant (Aspendora fork, Vikunja CIPP-4; page added for CIPP-3 Phase 2).
// Report only: /api/ListBreakGlassPosture reads the tenant and changes nothing.
import { Alert, Button, Container, Grid } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import { TabbedLayout } from "../../../../layouts/TabbedLayout";
import tabOptions from "./tabOptions.json";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { useSettings } from "../../../../hooks/use-settings";
import { ApiGetCall } from "../../../../api/ApiCall";

const Page = () => {
  const tenant = useSettings().currentTenant;
  const singleTenant = Boolean(tenant) && tenant !== "AllTenants";
  const report = ApiGetCall({
    url: "/api/ListBreakGlassPosture",
    data: { tenantFilter: tenant },
    queryKey: `BreakGlassPosture-${tenant}`,
    waiting: singleTenant,
  });
  const findings = Array.isArray(report.data?.Findings) ? report.data.Findings : [];
  const accounts = Array.isArray(report.data?.Accounts) ? report.data.Accounts : [];
  const count = (sev) => findings.filter((f) => f.Severity === sev).length;

  if (!singleTenant) {
    return (
      <Container maxWidth={false} sx={{ py: 2 }}>
        <Alert severity="info">Pick a single tenant to see its break-glass posture.</Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              { icon: <CippIcons.Error />, data: count("Error"), name: "Errors", color: "error" },
              { icon: <CippIcons.Warning />, data: count("Warning"), name: "Warnings", color: "warning" },
              { icon: <CippIcons.Info />, data: count("Info"), name: "Info", color: "info" },
              { icon: <CippIcons.Shield />, data: accounts.length, name: "Registered accounts", color: "secondary" },
            ]}
          />
        </Grid>
        <Grid size={12}>
          <CippDataTable
            title={`Break-glass posture - ${tenant}`}
            data={findings}
            isFetching={report.isFetching}
            queryKey={`BreakGlassPosture-${tenant}-table`}
            simpleColumns={["Severity", "Check", "Account", "Message", "Fix"]}
            cardButton={
              <Button
                startIcon={<CippIcons.Refresh />}
                disabled={report.isFetching}
                onClick={() => report.refetch()}
              >
                {report.isFetching ? "Checking..." : "Run check now"}
              </Button>
            }
          />
        </Grid>
        <Grid size={12}>
          <CippDataTable
            title="Registered accounts"
            data={accounts}
            isFetching={report.isFetching}
            queryKey={`BreakGlassPostureAccounts-${tenant}-table`}
            simpleColumns={[
              "UserPrincipalName",
              "Exists",
              "ActiveGlobalAdmin",
              "Methods",
              "LastSuccessfulSignIn",
            ]}
          />
        </Grid>
      </Grid>
    </Container>
  );
};

Page.getLayout = (page) => (
  <DashboardLayout>
    <TabbedLayout tabOptions={tabOptions}>{page}</TabbedLayout>
  </DashboardLayout>
);

export default Page;
