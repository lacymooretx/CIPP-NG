// SMS/voice MFA readiness (Aspendora fork, Vikunja CIPP-6).
// Report only: /api/ListSmsMfaReadiness reads the tenant and changes nothing. With All Tenants selected it
// shows the summaries stored by the last single-tenant view or SmsMfaReliance alert run.
import { Alert, Button, Container, Grid } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { useSettings } from "../../../../hooks/use-settings";
import { ApiGetCall } from "../../../../api/ApiCall";

const yesNo = (value) => (value === true ? "Yes" : value === false ? "No" : "Unknown");

const Page = () => {
  const tenant = useSettings().currentTenant;
  const allTenants = tenant === "AllTenants";
  const report = ApiGetCall({
    url: "/api/ListSmsMfaReadiness",
    data: { tenantFilter: tenant },
    queryKey: `SmsMfaReadiness-${tenant}`,
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
              weekly SMS/voice MFA reliance alert). Tenants never checked are not listed.
            </Alert>
          </Grid>
          <Grid size={12}>
            <CippDataTable
              title="SMS/voice MFA readiness - all tenants"
              data={rows}
              isFetching={report.isFetching}
              queryKey="SmsMfaReadiness-AllTenants-table"
              simpleColumns={[
                "Tenant",
                "ReadyToDisableSms",
                "ReadyToDisableVoice",
                "SmsState",
                "VoiceState",
                "CoveragePercent",
                "PhoneOnly",
                "AdminsPhoneOnly",
                "NoMfa",
                "AdminsNoMfa",
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
  const users = Array.isArray(report.data?.Users) ? report.data.Users : [];
  const affected = users.filter((u) => u.Category !== "Ready");
  const errors = Array.isArray(report.data?.Errors) ? report.data.Errors : [];

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {errors.length > 0 && (
          <Grid size={12}>
            <Alert severity="warning">Could not read everything: {errors.join("; ")}</Alert>
          </Grid>
        )}
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: summary?.ReadyToDisableSms ? <CippIcons.CheckCircle /> : <CippIcons.Cancel />,
                data: yesNo(summary?.ReadyToDisableSms),
                name: `Ready to disable SMS (SMS is ${summary?.SmsState ?? "unknown"})`,
                color: summary?.ReadyToDisableSms ? "success" : "error",
              },
              {
                icon: summary?.ReadyToDisableVoice ? <CippIcons.CheckCircle /> : <CippIcons.Cancel />,
                data: yesNo(summary?.ReadyToDisableVoice),
                name: `Ready to disable voice (voice is ${summary?.VoiceState ?? "unknown"})`,
                color: summary?.ReadyToDisableVoice ? "success" : "error",
              },
              {
                icon: <CippIcons.PhonelinkLock />,
                data: summary?.CoveragePercent != null ? `${summary.CoveragePercent}%` : "-",
                name: "Authenticator / passkey coverage",
                color: "info",
              },
              {
                icon: <CippIcons.PhoneAndroid />,
                data: summary ? `${summary.PhoneOnly} (${summary.AdminsPhoneOnly} admins)` : "-",
                name: "Users with only SMS/voice",
                color: "warning",
              },
            ]}
          />
        </Grid>
        <Grid size={12}>
          <CippDataTable
            title={`SMS/voice MFA readiness - ${tenant}`}
            data={findings}
            isFetching={report.isFetching}
            queryKey={`SmsMfaReadiness-${tenant}-findings`}
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
            title="Users affected (only SMS/voice, SMS/voice default, or no MFA)"
            data={affected}
            isFetching={report.isFetching}
            queryKey={`SmsMfaReadiness-${tenant}-users`}
            simpleColumns={[
              "UserPrincipalName",
              "DisplayName",
              "Category",
              "IsAdmin",
              "Methods",
              "DefaultMethod",
              "Licensed",
            ]}
          />
        </Grid>
      </Grid>
    </Container>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
