// Entra ID P1/P2 true-up (Aspendora fork, Vikunja CIPP-47).
// Report only: /api/ListEntraEntitlement reads the tenant and changes nothing. With All Tenants selected it
// shows the summaries stored by the last single-tenant view or EntraEntitlementGap alert run.
import { Alert, Button, Container, Grid } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { useSettings } from "../../../../hooks/use-settings";
import { ApiGetCall } from "../../../../api/ApiCall";

const seats = (pool, inScope) => (pool == null ? "-" : `${pool} seats / ${inScope} in scope`);

const Page = () => {
  const tenant = useSettings().currentTenant;
  const allTenants = tenant === "AllTenants";
  const report = ApiGetCall({
    url: "/api/ListEntraEntitlement",
    data: { tenantFilter: tenant },
    queryKey: `EntraEntitlement-${tenant}`,
    waiting: Boolean(tenant),
  });

  if (allTenants) {
    const rows = Array.isArray(report.data?.Results) ? report.data.Results : [];
    return (
      <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
        <Grid container spacing={2}>
          <Grid size={12}>
            <Alert severity="info">
              Stored results from the last check of each tenant (opening a single tenant here, or the
              Entra ID P1/P2 alert). Tenants never checked are not listed.
            </Alert>
          </Grid>
          <Grid size={12}>
            <CippDataTable
              title="Entra ID P1/P2 true-up - all tenants"
              data={rows}
              isFetching={report.isFetching}
              queryKey="EntraEntitlement-AllTenants-table"
              simpleColumns={[
                "Tenant",
                "CoveredP1",
                "CoveredP2",
                "P1Pool",
                "P1InScope",
                "P1Shortfall",
                "P1UserGaps",
                "P2Pool",
                "P2InScope",
                "P2Shortfall",
                "P2UserGaps",
                "P1InScopeWithReportOnly",
                "P2InScopeWithReportOnly",
                "EnabledMembers",
                "NonPersonExcluded",
                "GuestsInScope",
                "CheckedUtc",
              ]}
            />
          </Grid>
        </Grid>
      </Container>
    );
  }

  const summary = report.data?.Summary;
  const findings = Array.isArray(report.data?.Findings) ? report.data.Findings : [];
  const skus = Array.isArray(report.data?.Skus) ? report.data.Skus : [];
  const users = Array.isArray(report.data?.Users) ? report.data.Users : [];
  const gaps = users.filter((u) => u.P1Gap || u.P2Gap);
  const errors = Array.isArray(report.data?.Errors) ? report.data.Errors : [];
  const notes = Array.isArray(report.data?.Notes) ? report.data.Notes : [];

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {errors.length > 0 && (
          <Grid size={12}>
            <Alert severity="warning">Could not read everything, so nothing is reported: {errors.join("; ")}</Alert>
          </Grid>
        )}
        {notes.length > 0 && (
          <Grid size={12}>
            <Alert severity="info">{notes.join(" ")}</Alert>
          </Grid>
        )}
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: summary?.CoveredP1 ? <CippIcons.CheckCircle /> : <CippIcons.Cancel />,
                data: seats(summary?.P1Pool, summary?.P1InScope),
                name: `Entra ID P1 (${summary?.P1Shortfall ?? "-"} short)`,
                color: summary?.CoveredP1 ? "success" : "error",
              },
              {
                icon: summary?.CoveredP2 ? <CippIcons.CheckCircle /> : <CippIcons.Cancel />,
                data: seats(summary?.P2Pool, summary?.P2InScope),
                name: `Entra ID P2 (${summary?.P2Shortfall ?? "-"} short)`,
                color: summary?.CoveredP2 ? "success" : "error",
              },
              {
                icon: <CippIcons.PhonelinkLock />,
                data: summary ? `${summary.P1UserGaps} P1 / ${summary.P2UserGaps} P2` : "-",
                name: "In scope with no plan assigned (advisory)",
                color: "info",
              },
              {
                icon: <CippIcons.Schedule />,
                data: summary ? `${summary.P1InScopeWithReportOnly} P1 / ${summary.P2InScopeWithReportOnly} P2` : "-",
                name: "In scope if report-only policies were enabled",
                color: "info",
              },
            ]}
          />
        </Grid>
        <Grid size={12}>
          <CippDataTable
            title={`Entra ID P1/P2 true-up - ${tenant}`}
            data={findings}
            isFetching={report.isFetching}
            queryKey={`EntraEntitlement-${tenant}-findings`}
            simpleColumns={["Severity", "Check", "Message", "Fix"]}
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
            title="Licences carrying Entra ID P1 or P2"
            data={skus}
            isFetching={report.isFetching}
            queryKey={`EntraEntitlement-${tenant}-skus`}
            simpleColumns={["Sku", "Plans", "Status", "Enabled", "Consumed", "Suspended", "Warning"]}
          />
        </Grid>
        <Grid size={12}>
          <CippDataTable
            title="In scope with no plan assigned (true-up evidence, not failures)"
            data={gaps}
            isFetching={report.isFetching}
            queryKey={`EntraEntitlement-${tenant}-users`}
            simpleColumns={[
              "UserPrincipalName",
              "DisplayName",
              "P1Gap",
              "P2Gap",
              "InP1Scope",
              "InP2Scope",
              "HasP1Plan",
              "HasP2Plan",
            ]}
          />
        </Grid>
      </Grid>
    </Container>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
