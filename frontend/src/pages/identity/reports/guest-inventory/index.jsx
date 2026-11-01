// Guest inventory (Aspendora fork, Vikunja CIPP-14).
// /api/ListGuestInventory reads one tenant live and changes nothing. The only writes are the row actions below,
// which call the existing ExecDisableUser / RemoveUser endpoints after a confirmation, one request per selected guest.
// The client-facing PDF is the "Guest Access Review" report under Tools > Reports.
import { Alert, Button, Container, Grid } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { useSettings } from "../../../../hooks/use-settings";
import { usePermissions } from "../../../../hooks/use-permissions";
import { ApiGetCall } from "../../../../api/ApiCall";

const yesNoUnknown = (value) => (value === true ? "On" : value === false ? "Off" : "Unknown");

const Page = () => {
  const tenant = useSettings().currentTenant;
  const allTenants = !tenant || tenant === "AllTenants";
  const { checkPermissions } = usePermissions();
  const canWriteUser = checkPermissions(["Identity.User.ReadWrite"]);

  const report = ApiGetCall({
    url: "/api/ListGuestInventory",
    data: { tenantFilter: tenant },
    queryKey: `GuestInventory-${tenant}`,
    waiting: !allTenants,
  });

  if (allTenants) {
    return (
      <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
        <Alert severity="info">
          Select a single tenant. The guest inventory is read live, one tenant at a time.
        </Alert>
      </Container>
    );
  }

  const summary = report.data?.Summary;
  const context = report.data?.TenantContext;
  const guests = Array.isArray(report.data?.Guests) ? report.data.Guests : [];
  const errors = Array.isArray(report.data?.Errors) ? report.data.Errors : [];

  const actions = [
    {
      label: "Disable Guest",
      type: "POST",
      icon: <CippIcons.LockPerson />,
      url: "/api/ExecDisableUser",
      data: { ID: "id", Enable: false },
      confirmText: "Disable sign-in for [userPrincipalName]? The guest keeps its memberships and can be re-enabled.",
      multiPost: false,
      condition: (row) => canWriteUser && row.accountEnabled !== false,
    },
    {
      label: "Delete Guest",
      type: "POST",
      icon: <CippIcons.Delete />,
      url: "/api/RemoveUser",
      data: { ID: "id", userPrincipalName: "userPrincipalName" },
      confirmText:
        "Delete [userPrincipalName]? The guest loses access to every team, group and shared file. It can be restored from deleted users for 30 days.",
      multiPost: false,
      condition: () => canWriteUser,
    },
  ];

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {errors.length > 0 && (
          <Grid size={12}>
            <Alert severity="warning">Some data could not be read: {errors.join("; ")}</Alert>
          </Grid>
        )}
        {context && context.SignInActivityAvailable === false && (
          <Grid size={12}>
            <Alert severity="info">
              This tenant has no Entra ID P1 licence, so guest sign-in activity is not available. Stale guests
              cannot be detected; review them by age and inviter instead.
            </Alert>
          </Grid>
        )}
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: <CippIcons.Delete />,
                data: summary?.Remove ?? "-",
                name: `Remove (invite unredeemed ${report.data?.PendingDays ?? 30}+ days, or disabled and unused)`,
                color: summary?.Remove ? "error" : "success",
              },
              {
                icon: <CippIcons.LockPerson />,
                data: summary?.Disable ?? "-",
                name: `Disable (no sign-in ${report.data?.StaleDays ?? 90}+ days)`,
                color: summary?.Disable ? "warning" : "success",
              },
              {
                icon: <CippIcons.Visibility />,
                data: summary?.Review ?? "-",
                name: "Review (personal account, inviter gone, activity unknown)",
                color: summary?.Review ? "warning" : "success",
              },
              {
                icon: <CippIcons.CheckCircle />,
                data: summary ? `${summary.Keep} of ${summary.Total}` : "-",
                name: "Keep",
                color: "info",
              },
            ]}
          />
        </Grid>
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: <CippIcons.Share />,
                data: yesNoUnknown(context?.SharePointB2BIntegration),
                name: "SharePoint/OneDrive Entra B2B integration (On = shared-with people become Entra guests)",
                color: "info",
              },
              {
                icon: <CippIcons.Public />,
                data: context?.SharePointSharingCapability || "Unknown",
                name: "SharePoint external sharing level",
                color: "info",
              },
              {
                icon: <CippIcons.PersonAdd />,
                data: context?.AllowInvitesFrom || "Unknown",
                name: "Who can invite guests",
                color: context?.AllowInvitesFrom === "everyone" ? "warning" : "info",
              },
              {
                icon: <CippIcons.Group />,
                data: summary ? `${summary.Pending} / ${summary.Personal} / ${summary.InviterGone}` : "-",
                name: "Unredeemed / personal accounts / inviter disabled",
                color: "info",
              },
            ]}
          />
        </Grid>
        <Grid size={12}>
          <CippDataTable
            title={`Guest inventory - ${tenant}`}
            data={guests}
            isFetching={report.isFetching}
            queryKey={`GuestInventory-${tenant}-table`}
            actions={actions}
            simpleColumns={[
              "recommendedAction",
              "displayName",
              "mail",
              "reasons",
              "accountType",
              "externalUserState",
              "pendingSinceDays",
              "daysSinceSignIn",
              "invitedBy",
              "inviterState",
              "teams",
              "groupCount",
              "accountEnabled",
              "createdDateTime",
            ]}
            cardButton={
              <Button
                startIcon={<CippIcons.Refresh />}
                disabled={report.isFetching}
                onClick={() => report.refetch()}
              >
                {report.isFetching ? "Reading..." : "Refresh"}
              </Button>
            }
          />
        </Grid>
      </Grid>
    </Container>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
