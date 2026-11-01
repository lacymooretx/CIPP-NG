// Standing-admin and least-privilege role report (Aspendora fork, Vikunja CIPP-15).
// Report only: /api/ListRoleAssignmentReport reads the tenant (and the partner's GDAP relationships) and changes
// nothing.
import { Alert, Button, Container, Grid } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { useSettings } from "../../../../hooks/use-settings";
import { ApiGetCall } from "../../../../api/ApiCall";

const Page = () => {
  const tenant = useSettings().currentTenant;
  const singleTenant = Boolean(tenant) && tenant !== "AllTenants";
  const report = ApiGetCall({
    url: "/api/ListRoleAssignmentReport",
    data: { tenantFilter: tenant },
    queryKey: `RoleAssignmentReport-${tenant}`,
    waiting: singleTenant,
  });
  const list = (key) => (Array.isArray(report.data?.[key]) ? report.data[key] : []);
  const summary = report.data?.Summary;
  const findings = list("Findings");
  const errors = list("Errors");

  if (!singleTenant) {
    return (
      <Container maxWidth={false} sx={{ py: 2 }}>
        <Alert severity="info">Pick a single tenant to see its role assignment report.</Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {errors.length > 0 && (
          <Grid size={12}>
            <Alert severity="warning">Could not read everything: {errors.join("; ")}</Alert>
          </Grid>
        )}
        {summary && summary.PimAvailable === false && (
          <Grid size={12}>
            <Alert severity="info">
              No Entra ID P2 in this tenant: PIM schedules cannot be read, so every active assignment is
              treated as standing and PIM-eligible assignments are not shown.
            </Alert>
          </Grid>
        )}
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: <CippIcons.AdminPanelSettings />,
                data: summary?.StandingGlobalAdmins ?? "-",
                name: "Standing Global Admins (excl. break-glass)",
                color: "error",
              },
              {
                icon: <CippIcons.Person />,
                data: summary?.PrivilegedUsers ?? "-",
                name: "Users with privileged roles",
                color: "secondary",
              },
              {
                icon: <CippIcons.PersonOff />,
                data: summary?.InactivePrivileged ?? "-",
                name: "Inactive privileged accounts",
                color: "warning",
              },
              {
                icon: <CippIcons.VpnKey />,
                data: summary?.GdapRelationshipsWithGlobalAdmin ?? "-",
                name: "GDAP relationships with Global Admin",
                color: "warning",
              },
            ]}
          />
        </Grid>
        <Grid size={12}>
          <CippDataTable
            title={`Role assignment findings - ${tenant}`}
            data={findings}
            isFetching={report.isFetching}
            queryKey={`RoleAssignmentReport-${tenant}-findings`}
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
            title="Least-privilege recommendations for standing Global Admins"
            data={list("Recommendations")}
            isFetching={report.isFetching}
            queryKey={`RoleAssignmentReport-${tenant}-recommendations`}
            simpleColumns={["UserPrincipalName", "SuggestedRoles", "Evidence", "CurrentRoles"]}
          />
        </Grid>
        <Grid size={12}>
          <CippDataTable
            title="All role assignments"
            data={list("Assignments")}
            isFetching={report.isFetching}
            queryKey={`RoleAssignmentReport-${tenant}-assignments`}
            simpleColumns={[
              "Principal",
              "PrincipalType",
              "Role",
              "Privileged",
              "Kind",
              "Permanent",
              "Via",
              "LastSignIn",
              "BreakGlass",
              "AccountEnabled",
            ]}
          />
        </Grid>
        <Grid size={12}>
          <CippDataTable
            title="Least-privileged role by task (Microsoft Learn)"
            data={list("Tasks")}
            isFetching={report.isFetching}
            queryKey={`RoleAssignmentReport-${tenant}-tasks`}
            simpleColumns={["Task", "Role", "Notes"]}
          />
        </Grid>
      </Grid>
    </Container>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
