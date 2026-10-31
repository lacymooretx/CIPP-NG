// GDAP relationship and token health (Aspendora fork, Vikunja CIPP-2).
// Shows the latest daily report from /api/ListGDAPHealth and lets an operator run the check now
// or enable auto-extend on a relationship that is expiring.
import { Button, Container, Grid, Stack, Typography } from "@mui/material";
import { TabbedLayout } from "../../../layouts/TabbedLayout";
import { Layout as DashboardLayout } from "../../../layouts/index";
import tabOptions from "./tabOptions";
import CippTablePage from "../../../components/CippComponents/CippTablePage";
import { CippInfoBar } from "../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../utils/icon-registry";
import { ApiGetCall, ApiPostCall } from "../../../api/ApiCall";

const queryKey = "ListGDAPHealth";

const actions = [
  {
    label: "Enable automatic extension",
    type: "POST",
    url: "/api/ExecAutoExtendGDAP",
    data: { ID: "RelationshipId" },
    confirmText:
      "Enable 180-day auto-extend for [Relationship] ([Tenant])? The finding clears at the next health check (use Run check now).",
    color: "info",
    icon: <CippIcons.HourglassBottom />,
    relatedQueryKeys: [queryKey, "ListGDAPRelationships"],
    condition: (row) => row?.Category === "Expiring" && row?.AutoExtendEligible === true,
  },
  {
    label: "View Relationship",
    link: "/tenant/gdap-management/relationships/relationship?id=[RelationshipId]",
    color: "primary",
    icon: <CippIcons.EyeIcon />,
    condition: (row) => Boolean(row?.RelationshipId),
  },
  {
    label: "Open Relationship in Partner Center",
    link: "https://partner.microsoft.com/en-us/dashboard/commerce2/customers/[TenantId]/adminrelationships/[RelationshipId]",
    color: "info",
    icon: <CippIcons.Launch />,
    condition: (row) => Boolean(row?.RelationshipId && row?.TenantId),
  },
];

const simpleColumns = [
  "Severity",
  "Tenant",
  "Category",
  "Relationship",
  "EndDateTime",
  "AutoExtendDuration",
  "Message",
];

const filters = [
  { filterName: "Errors", value: [{ id: "Severity", value: "Error" }], type: "column" },
  { filterName: "Warnings", value: [{ id: "Severity", value: "Warning" }], type: "column" },
  { filterName: "Pending invites", value: [{ id: "Category", value: "Pending" }], type: "column" },
];

const Page = () => {
  const report = ApiGetCall({ url: "/api/ListGDAPHealth", queryKey });
  const runCheck = ApiPostCall({ relatedQueryKeys: [queryKey] });
  const data = report.data ?? {};
  const findings = Array.isArray(data.Findings) ? data.Findings : [];
  const summary = data.Summary ?? {};
  const generated = data.GeneratedUtc ? new Date(data.GeneratedUtc).toLocaleString() : "Never";
  const collectionErrors = Array.isArray(data.CollectionErrors) ? data.CollectionErrors : [];

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching || runCheck.isPending}
            data={[
              { icon: <CippIcons.Error />, data: summary.Errors ?? 0, name: "Errors", color: "error" },
              { icon: <CippIcons.Warning />, data: summary.Warnings ?? 0, name: "Warnings", color: "warning" },
              { icon: <CippIcons.Info />, data: summary.Info ?? 0, name: "Pending invites", color: "info" },
              { icon: <CippIcons.Schedule />, data: generated, name: "Last checked", color: "secondary" },
            ]}
          />
        </Grid>
        {collectionErrors.length > 0 && (
          <Grid size={12}>
            <Typography color="error" variant="body2">
              The last check could not read everything: {collectionErrors.join("; ")}
            </Typography>
          </Grid>
        )}
        <Grid size={12}>
          <CippTablePage
            title="GDAP & Token Health"
            tenantInTitle={false}
            data={findings}
            isFetching={report.isFetching}
            // Rows come from the report query above; the table only needs its own cache key.
            queryKey={`${queryKey}-table`}
            actions={actions}
            offCanvas={{ actions, extendedInfoFields: [...simpleColumns, "Key", "DaysLeft", "Managed", "Covered"] }}
            simpleColumns={simpleColumns}
            filters={filters}
            maxHeightOffset="560px"
            cardButton={
              <Stack direction="row" spacing={1}>
                <Button
                  startIcon={<CippIcons.Refresh />}
                  disabled={runCheck.isPending}
                  onClick={() =>
                    runCheck.mutate({ url: "/api/ListGDAPHealth", data: { Refresh: true } })
                  }
                >
                  {runCheck.isPending ? "Checking..." : "Run check now"}
                </Button>
              </Stack>
            }
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
