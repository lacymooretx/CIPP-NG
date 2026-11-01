// Abused TLD exposure (Aspendora fork, Vikunja CIPP-30).
// Audit-only view of what an abused-TLD Tenant Allow/Block List block would stop (inbound) or break (outbound),
// from /api/ListTldExposure, plus the shipped block templates from /api/ExecTldBlockTemplates. Saving the
// templates puts them in the template library; it deploys nothing to any tenant.
import { useState } from "react";
import { Alert, Button, Stack, Typography } from "@mui/material";
import { Grid } from "@mui/system";
import { useForm } from "react-hook-form";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import CippFormComponent from "../../../../components/CippComponents/CippFormComponent";
import CippButtonCard from "../../../../components/CippCards/CippButtonCard";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippApiDialog } from "../../../../components/CippComponents/CippApiDialog";
import { CippIcons } from "../../../../utils/icon-registry";
import { ApiGetCall, ApiPostCall } from "../../../../api/ApiCall";
import { useSettings } from "../../../../hooks/use-settings";
import { useDialog } from "../../../../hooks/use-dialog";
import { getCippError } from "../../../../utils/get-cipp-error";

const tldColumns = [
  "Tld",
  "SenderRisk",
  "UrlRisk",
  "InboundMessages",
  "InboundDelivered",
  "InboundFiltered",
  "OutboundMessages",
  "InternalSenders",
];

const Page = () => {
  const tenant = useSettings().currentTenant;
  const singleTenant = Boolean(tenant) && tenant !== "AllTenants";
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const saveDialog = useDialog();
  const formControl = useForm({ defaultValues: { Days: 10, MaxPages: 10, Tlds: "" } });

  const audit = ApiPostCall({ onResult: (r) => setReport(r) });
  const catalog = ApiGetCall({
    url: "/api/ExecTldBlockTemplates",
    data: { Action: "Preview" },
    queryKey: "TldBlockTemplates",
  });

  const run = () => {
    const v = formControl.getValues();
    setReport(null);
    setError(null);
    audit.mutate(
      { url: "/api/ListTldExposure", data: { tenantFilter: tenant, Days: Number(v.Days) || 10, MaxPages: Number(v.MaxPages) || 10, Tlds: v.Tlds } },
      { onError: (e) => setError(e?.response?.data?.Results ?? getCippError(e)) }
    );
  };

  const templates = Array.isArray(catalog.data?.Templates) ? catalog.data.Templates : [];
  const tlds = Array.isArray(catalog.data?.Tlds) ? catalog.data.Tlds : [];

  return (
    <Stack spacing={2} sx={{ px: 3, py: 2 }}>
      <CippButtonCard
        title="Abused TLD exposure (audit only)"
        CardButton={
          <Button variant="contained" startIcon={<CippIcons.Search />} disabled={!singleTenant || audit.isPending} onClick={run}>
            {audit.isPending ? "Reading message trace..." : "Run audit"}
          </Button>
        }
      >
        {!singleTenant && <Alert severity="info">Pick a single tenant to run the audit.</Alert>}
        <Grid container spacing={1.5}>
          <Grid size={{ xs: 12, md: 3 }}>
            <CippFormComponent type="number" name="Days" label="Days back (1-90)" formControl={formControl} />
          </Grid>
          <Grid size={{ xs: 12, md: 3 }}>
            <CippFormComponent
              type="number"
              name="MaxPages"
              label="Max pages (5000 rows each)"
              helperText="Default 10; busy tenants need more"
              formControl={formControl}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 6 }}>
            <CippFormComponent
              type="textField"
              name="Tlds"
              label="TLDs (optional)"
              helperText="e.g. xyz,top - leave empty for the full abused-TLD list"
              formControl={formControl}
            />
          </Grid>
        </Grid>
        <Typography variant="caption" color="text.secondary">
          Counts mail from senders under these TLDs, and mail your users sent to them: a *.TLD sender block quarantines
          the first and makes Microsoft reject the second. Changes nothing.
        </Typography>
      </CippButtonCard>

      {error && <Alert severity="error">{String(error)}</Alert>}

      {report && (
        <>
          <CippInfoBar
            data={[
              { icon: <CippIcons.Inbox />, data: report.InboundMessages, name: "Inbound messages (would be blocked)", color: "warning" },
              { icon: <CippIcons.Outbox />, data: report.OutboundMessages, name: "Outbound messages (would bounce)", color: "error" },
              { icon: <CippIcons.ManageSearch />, data: report.RowsScanned, name: "Trace rows read", color: "info" },
              { icon: <CippIcons.History />, data: report.CoveredFrom?.Display ?? "-", name: report.Truncated ? "Covered from (page cap hit)" : "Covered from", color: report.Truncated ? "warning" : "secondary" },
            ]}
          />
          {(report.Notes ?? []).map((n, i) => (
            <Alert key={i} severity={/cap/.test(n) ? "warning" : "info"}>
              {n}
            </Alert>
          ))}
          <CippDataTable title={`By TLD - ${report.Tenant}`} data={report.ByTld ?? []} simpleColumns={tldColumns} queryKey={`TldExposure-${tenant}-tld`} />
          <CippDataTable title="Top sender domains (inbound)" data={report.TopSenderDomains ?? []} simpleColumns={["Domain", "Tld", "Count"]} queryKey={`TldExposure-${tenant}-senders`} />
          <CippDataTable
            title="Top recipient domains (outbound - would break)"
            data={report.TopOutboundDomains ?? []}
            simpleColumns={["Domain", "Tld", "Count"]}
            queryKey={`TldExposure-${tenant}-outbound`}
          />
        </>
      )}

      <CippDataTable
        title="Abused TLD block templates (not deployed)"
        data={templates}
        isFetching={catalog.isFetching}
        simpleColumns={["templateName", "listType", "listMethod", "entries", "description"]}
        queryKey="TldBlockTemplates-table"
        cardButton={
          <Button startIcon={<CippIcons.Save />} onClick={saveDialog.handleOpen}>
            Save to template library
          </Button>
        }
      />
      <CippDataTable
        title={`TLD list and false-positive risk (${catalog.data?.Version ?? ""})`}
        data={tlds}
        isFetching={catalog.isFetching}
        simpleColumns={["tld", "senderRisk", "urlRisk", "note"]}
        queryKey="TldBlockTemplates-tlds"
      />
      <CippApiDialog
        createDialog={saveDialog}
        title="Save the abused-TLD templates"
        fields={[]}
        api={{
          type: "POST",
          url: "/api/ExecTldBlockTemplates",
          data: { Action: "!Save" },
          confirmText:
            "Save the three abused-TLD templates to the Tenant Allow/Block List template library? This deploys nothing: a template only reaches a tenant when you add it to a standards template with remediation on. Saving again updates them in place.",
          relatedQueryKeys: ["ListTenantAllowBlockListTemplates*"],
        }}
      />
    </Stack>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
