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

// Microsoft-provided SMS/voice retirement (CIPP-46). Days are counted by the backend from today's US Central date.
const daysText = (days) =>
  days == null ? "-" : days > 0 ? `${days} days` : days === 0 ? "Today" : `Passed ${-days} days ago`;
const campaignText = (summary) => {
  if (!summary || !summary.RegistrationCampaignState || summary.RegistrationCampaignState === "unknown") {
    return "Unknown";
  }
  // Graph calls the portal's "Microsoft managed" state "default".
  const state =
    summary.RegistrationCampaignState === "default" ? "Microsoft managed" : summary.RegistrationCampaignState;
  return summary.RegistrationCampaignMethods ? `${state}: ${summary.RegistrationCampaignMethods}` : state;
};
// Would Conditional Access stop the passkey registration Microsoft will require (CIPP-53)?
const caBlockText = (value) =>
  value === "Yes"
    ? "Yes"
    : value === "ReportOnly"
      ? "Once report-only policies are enforced"
      : value === "No"
        ? "No"
        : "Unknown";
const caBlockColor = (value) =>
  value === "Yes" ? "error" : value === "No" ? "success" : "warning";
const optOutText = (value) =>
  value === "true" ? "Opted out (until 1 Feb 2027)" : value === "false" ? "Not opted out" : "Unknown";

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
                "ReadyByFeb2027",
                "RetirementFebruary2027",
                "RetirementJuly2027",
                "NearestDeadline",
                "NearestDeadlineDaysRemaining",
                "PasskeyDynamicMigrationOptOut",
                "RegistrationCampaignState",
                "RegistrationCampaignMethods",
                "PasskeyState",
                "TelephonyProvider",
                "CaWouldBlockRegistration",
                "CaBlockEnforcedPolicies",
                "CaBlockReportOnlyPolicies",
                "CaBlockPhoneOnlyUsers",
                "RegisterSecurityInfoPolicy",
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
  const guests = Array.isArray(report.data?.Guests) ? report.data.Guests : [];
  const nearestDays = summary?.NearestDeadlineDaysRemaining;

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
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: <CippIcons.CalendarMonth />,
                data: summary
                  ? summary.NearestDeadline
                    ? `${summary.NearestDeadline} (${summary.NearestDeadlineUsers} users)`
                    : "None"
                  : "-",
                name: `SMS/voice retirement deadline (Feb: ${summary?.RetirementFebruary2027 ?? "-"}, Jul: ${
                  summary?.RetirementJuly2027 ?? "-"
                })`,
                color: summary && !summary.NearestDeadline ? "success" : "error",
              },
              {
                icon: <CippIcons.HourglassEmpty />,
                data: summary ? (summary.NearestDeadline ? daysText(nearestDays) : "Ready") : "-",
                name: `Days remaining (ready by 1 Feb 2027: ${yesNo(summary?.ReadyByFeb2027)})`,
                color:
                  !summary || !summary.NearestDeadline
                    ? "success"
                    : nearestDays != null && nearestDays <= 90
                      ? "error"
                      : "warning",
              },
              {
                icon: <CippIcons.Schedule />,
                data: optOutText(summary?.PasskeyDynamicMigrationOptOut),
                name: "Passkey auto-enablement opt-out (does not stop enforcement)",
                color: summary?.PasskeyDynamicMigrationOptOut === "true" ? "warning" : "info",
              },
              {
                icon: <CippIcons.Fingerprint />,
                data: campaignText(summary),
                name: `Registration campaign (passkeys ${summary?.PasskeyState ?? "unknown"}${
                  summary?.PasskeyScope === "Groups" ? ` for ${summary.PasskeyGroups} group(s)` : ""
                })`,
                color: summary?.RegistrationCampaignOk ? "success" : "warning",
              },
            ]}
          />
        </Grid>
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: <CippIcons.Block />,
                data: caBlockText(summary?.CaWouldBlockRegistration),
                name: `CA would block registration${
                  summary?.CaBlockEnforcedPolicies || summary?.CaBlockReportOnlyPolicies
                    ? ` (${summary?.CaBlockEnforcedPolicies || summary?.CaBlockReportOnlyPolicies})`
                    : ""
                }`,
                color: caBlockColor(summary?.CaWouldBlockRegistration),
              },
              {
                icon: <CippIcons.PhoneAndroid />,
                data: summary?.CaBlockPhoneOnlyUsers ?? "-",
                name: "SMS/voice-only accounts in scope of an enforced block (up to)",
                color: summary?.CaBlockPhoneOnlyUsers > 0 ? "error" : "success",
              },
              {
                icon: <CippIcons.Policy />,
                data: summary?.RegisterSecurityInfoPolicy ?? "Unknown",
                name: "Register security info policy",
                color: summary?.RegisterSecurityInfoPolicy === "Enforced" ? "success" : "warning",
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
              "RetirementDate",
              "DaysRemaining",
              "RetirementBasis",
            ]}
          />
        </Grid>
        {guests.length > 0 && (
          <Grid size={12}>
            <CippDataTable
              title="Guests whose only MFA is SMS/voice (external users: 1 Jul 2027; internal guests: 1 Feb 2027)"
              data={guests}
              isFetching={report.isFetching}
              queryKey={`SmsMfaReadiness-${tenant}-guests`}
              simpleColumns={[
                "UserPrincipalName",
                "DisplayName",
                "Methods",
                "RetirementBasis",
                "RetirementDate",
                "DaysRemaining",
              ]}
            />
          </Grid>
        )}
      </Grid>
    </Container>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
