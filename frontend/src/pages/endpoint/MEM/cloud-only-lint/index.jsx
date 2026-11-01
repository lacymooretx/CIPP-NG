// Cloud-only policy lint (Aspendora fork, Vikunja CIPP-28).
// Read-only report from /api/ListIntuneCloudOnlyLint: Intune settings that misbehave or do nothing on Entra
// joined (cloud-only) devices, for the current tenant's live policies or for one saved template
// (?templateId=<GUID>, opened from the Policy Templates list).
import { Alert, Button, Container, Grid, Typography } from "@mui/material";
import NextLink from "next/link";
import { useRouter } from "next/router";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import CippTablePage from "../../../../components/CippComponents/CippTablePage";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { ApiGetCall } from "../../../../api/ApiCall";
import { useSettings } from "../../../../hooks/use-settings";

const simpleColumns = [
  "Severity",
  "Relevance",
  "PolicyName",
  "PolicyType",
  "Title",
  "Settings",
  "Symptom",
  "Alternative",
  "Source",
];

const filters = [
  { filterName: "High", value: [{ id: "Severity", value: "High" }], type: "column" },
  { filterName: "Applies to this tenant", value: [{ id: "Relevance", value: "Applies" }], type: "column" },
  { filterName: "Assigned policies", value: [{ id: "Assigned", value: "Yes" }], type: "column" },
];

const Page = () => {
  const router = useRouter();
  const tenant = useSettings().currentTenant;
  const singleTenant = Boolean(tenant) && tenant !== "AllTenants";
  const templateId = typeof router.query.templateId === "string" ? router.query.templateId : "";
  const templateMode = Boolean(templateId);
  const canRun = templateMode || singleTenant;

  const queryKey = `ListIntuneCloudOnlyLint-${tenant}-${templateId || "tenant"}`;
  const data = {};
  if (singleTenant) data.tenantFilter = tenant;
  if (templateMode) data.templateId = templateId;
  const report = ApiGetCall({
    url: "/api/ListIntuneCloudOnlyLint",
    data,
    queryKey,
    waiting: canRun,
  });

  const body = report.data ?? {};
  const findings = Array.isArray(body.Findings) ? body.Findings : [];
  const summary = body.Summary ?? {};
  const bySeverity = summary.BySeverity ?? {};
  const context = body.Context ?? null;
  const errors = Array.isArray(body.Errors) ? body.Errors : [];
  const template = body.Template ?? null;

  const contextText = context
    ? `Windows devices: ${context.WindowsDevices ?? "?"} (Entra joined / cloud-only ${context.CloudOnlyDevices ?? "?"}, hybrid joined ${context.HybridDevices ?? "?"}, registered ${context.RegisteredDevices ?? "?"}). On-premises directory sync: ${context.DirectorySynced === true ? "yes" : context.DirectorySynced === false ? "no" : "unknown"}.`
    : null;

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {!canRun && (
          <Grid size={12}>
            <Alert severity="info">
              Select a single tenant to lint its Intune policies, or open a template from Policy Templates with
              the Cloud-only Lint action.
            </Alert>
          </Grid>
        )}
        {templateMode && (
          <Grid size={12}>
            <Alert
              severity="info"
              action={
                <Button component={NextLink} href="/endpoint/MEM/cloud-only-lint" size="small">
                  Lint the tenant instead
                </Button>
              }
            >
              Linting template {template?.DisplayName ? `"${template.DisplayName}"` : templateId}
              {template?.Type ? ` (${template.Type})` : ""}.
              {singleTenant ? ` Relevance uses ${tenant}'s devices.` : " Select a tenant to see whether it has cloud-only devices."}
            </Alert>
          </Grid>
        )}
        {report.isError && (
          <Grid size={12}>
            <Alert severity="error">{report.error?.response?.data?.Results ?? "The lint failed."}</Alert>
          </Grid>
        )}
        {canRun && (
          <>
            <Grid size={12}>
              <CippInfoBar
                isFetching={report.isFetching}
                data={[
                  { icon: <CippIcons.Policy />, data: summary.PoliciesChecked ?? 0, name: "Policies checked", color: "secondary" },
                  { icon: <CippIcons.Error />, data: bySeverity.High ?? 0, name: "High", color: "error" },
                  { icon: <CippIcons.Warning />, data: (bySeverity.Medium ?? 0) + (bySeverity.Low ?? 0), name: "Medium / Low", color: "warning" },
                  { icon: <CippIcons.Info />, data: bySeverity.Info ?? 0, name: "Info", color: "info" },
                  { icon: <CippIcons.Devices />, data: context?.CloudOnlyDevices ?? "-", name: "Cloud-only devices", color: "primary" },
                ]}
              />
            </Grid>
            {contextText && (
              <Grid size={12}>
                <Typography variant="body2" color="text.secondary">
                  {contextText} A finding marked "Not applicable" has no Entra joined devices to affect in this tenant.
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
                title={templateMode ? "Cloud-only Lint: Template" : "Cloud-only Lint"}
                tenantInTitle={!templateMode}
                data={findings}
                isFetching={report.isFetching}
                // Rows come from the report query above; the table only needs its own cache key.
                queryKey={`${queryKey}-table`}
                offCanvas={{
                  extendedInfoFields: [
                    ...simpleColumns,
                    "Why",
                    "RelevanceReason",
                    "Assigned",
                    "MatchedVia",
                    "ValueVerified",
                    "RuleId",
                    "PolicyId",
                    "Sources",
                  ],
                }}
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
