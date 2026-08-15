import { useState } from "react";
import {
  Button,
  Container,
  Stack,
  Typography,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Chip,
} from "@mui/material";
import { Grid } from "@mui/system";
import {
  Description,
  Download,
  Visibility,
  Schedule,
  PictureAsPdf,
} from "@mui/icons-material";
import { useForm, useWatch } from "react-hook-form";
import { Layout as DashboardLayout } from "../../../layouts/index.js";
import CippButtonCard from "../../../components/CippCards/CippButtonCard";
import CippFormComponent from "../../../components/CippComponents/CippFormComponent";
import { CippFormTenantSelector } from "../../../components/CippComponents/CippFormTenantSelector";
import { CippApiResults } from "../../../components/CippComponents/CippApiResults";
import { ApiPostCall, ApiGetCall } from "../../../api/ApiCall";

const GRADE_COLOR = { A: "success", B: "success", C: "warning", D: "warning", F: "error" };

// Report catalogue. Every type runs through the generic dispatcher: on-demand
// /api/ExecReport?ReportType=…, scheduled via command Push-ExecReport { ReportType }.
const ENDPOINT = "/api/ExecReport";
const COMMAND = "Push-ExecReport";
const REPORT_TYPES = [
  { label: "Microsoft 365 Security Report", value: "Security" },
  { label: "External Forwarding Report", value: "Forwarding" },
  { label: "Registered Applications Report", value: "Applications" },
  { label: "Intune Compliance Report", value: "IntuneCompliance" },
  { label: "Intune Configuration Document", value: "IntuneConfig" },
  { label: "License Report", value: "Licenses" },
  { label: "Administrator Report", value: "AdminTracker" },
  { label: "Domain Health Report", value: "DomainInfo" },
  { label: "Mailbox Access Report", value: "AccessTracker" },
  { label: "Accounts & Licensing Report", value: "Accounts" },
  { label: "User Login Report", value: "LoginTracker" },
  { label: "Mailbox Size Report", value: "MailboxSize" },
  { label: "Mailbox Permissions Report", value: "MailboxFolderPermissions" },
  { label: "SharePoint & OneDrive Usage Report", value: "SharePointUsage" },
  { label: "External Sharing Report", value: "SharingTracker" },
  { label: "Site Permissions Report", value: "SitePermissions" },
  { label: "Copilot Readiness Report", value: "Copilot" },
].map((r) => ({ ...r, endpoint: ENDPOINT, command: COMMAND }));

const tenantValue = (t) => (t && typeof t === "object" ? t.value : t);

const Page = () => {
  const formControl = useForm({
    mode: "onChange",
    defaultValues: { reportType: REPORT_TYPES[0] },
  });
  const tenant = useWatch({ control: formControl.control, name: "tenantFilter" });
  const reportType = useWatch({ control: formControl.control, name: "reportType" });

  const [lastReport, setLastReport] = useState(null); // { name, html }
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const scheduleForm = useForm({
    mode: "onChange",
    defaultValues: {
      recurrence: { label: "Every 30 days", value: "30d" },
      postExecution: [],
      allTenants: false,
      connectWiseTicket: false,
    },
  });

  const selected = reportType?.value
    ? REPORT_TYPES.find((r) => r.value === reportType.value)
    : REPORT_TYPES[0];
  const tenantFilter = tenantValue(tenant);

  const openHtml = (html) => {
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank", "noopener,noreferrer");
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  };
  const downloadHtml = (name, html) => {
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name || "report.html";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };
  // Print to PDF via the browser (report has a print stylesheet).
  const printPdf = (html) => {
    const w = window.open("", "_blank");
    if (!w) return;
    w.document.open();
    w.document.write(html);
    w.document.close();
    w.focus();
    setTimeout(() => w.print(), 600);
  };

  // Report history (trend) for the selected tenant + type.
  const history = ApiGetCall({
    url: "/api/ListReportHistory",
    data: { TenantFilter: tenantFilter, ReportType: selected?.value },
    queryKey: `reporthistory-${tenantFilter}-${selected?.value}`,
    waiting: !!tenantFilter,
  });

  const generateCall = ApiPostCall({
    onResult: (res) => {
      if (res?.ReportHtml) {
        setLastReport({ name: res.ReportName, html: res.ReportHtml });
        openHtml(res.ReportHtml);
      }
    },
  });

  const handleGenerate = () => {
    setLastReport(null);
    generateCall.mutate({
      url: selected.endpoint,
      data: { TenantFilter: tenantFilter, ReportType: selected.value },
    });
  };

  const scheduleCall = ApiPostCall({ relatedQueryKeys: ["ScheduledTasks"] });
  const handleSchedule = () => {
    const values = scheduleForm.getValues();
    const target = values.allTenants ? "AllTenants" : tenantFilter;
    scheduleCall.mutate({
      url: "/api/AddScheduledItem",
      data: {
        TenantFilter: target,
        Name: values.scheduleName || `${selected.label} - ${target}`,
        command: { label: selected.command, value: selected.command },
        parameters: {
          TenantFilter: target,
          ReportType: selected.value,
          ConnectWiseTicket: !!values.connectWiseTicket,
        },
        ScheduledTime: Math.floor(Date.now() / 1000),
        Recurrence: values.recurrence || { value: "30d", label: "Every 30 days" },
        postExecution: values.postExecution || [],
        taskType: { value: "scheduled", label: "Scheduled" },
        reference: `report-${selected.value}-${target}`,
      },
    });
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Stack spacing={1} sx={{ mb: 3 }}>
        <Typography variant="h4">Reports</Typography>
        <Typography variant="body2" color="text.secondary">
          Generate a branded Microsoft 365 report for a tenant on demand, or schedule it to be
          emailed as an attachment on a recurring basis. Branding (logo &amp; colour) comes from
          Settings &rarr; Branding.
        </Typography>
      </Stack>
      <Grid container spacing={3}>
        <Grid size={{ xs: 12 }}>
          <CippButtonCard
            title="Generate Report"
            CardButton={
              <Stack direction="row" spacing={1}>
                <Button
                  variant="contained"
                  startIcon={<Visibility />}
                  disabled={!tenantFilter || generateCall.isPending}
                  onClick={handleGenerate}
                >
                  {generateCall.isPending ? "Generating…" : "Generate & Preview"}
                </Button>
                {lastReport && (
                  <Button
                    variant="outlined"
                    startIcon={<Download />}
                    onClick={() => downloadHtml(lastReport.name, lastReport.html)}
                  >
                    Download
                  </Button>
                )}
                {lastReport && (
                  <Button
                    variant="outlined"
                    startIcon={<PictureAsPdf />}
                    onClick={() => printPdf(lastReport.html)}
                  >
                    PDF
                  </Button>
                )}
                <Button
                  variant="outlined"
                  startIcon={<Schedule />}
                  disabled={!tenantFilter}
                  onClick={() => setScheduleOpen(true)}
                >
                  Schedule
                </Button>
              </Stack>
            }
          >
            <Stack spacing={2}>
              <CippFormComponent
                type="autoComplete"
                name="reportType"
                label="Report"
                formControl={formControl}
                options={REPORT_TYPES.map((r) => ({ label: r.label, value: r.value }))}
                multiple={false}
                creatable={false}
              />
              <CippFormTenantSelector
                formControl={formControl}
                name="tenantFilter"
                type="single"
                allTenants={false}
              />
              <CippApiResults apiObject={generateCall} />
              {lastReport && (
                <Alert severity="success" icon={<Description />}>
                  Generated <strong>{lastReport.name}</strong>. It opened in a new tab; use
                  Download to save it.
                </Alert>
              )}
            </Stack>
          </CippButtonCard>
        </Grid>

        {tenantFilter && history.isSuccess && Array.isArray(history.data) && history.data.length > 0 && (
          <Grid size={{ xs: 12 }}>
            <CippButtonCard title={`History — ${selected.label}`}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Date</TableCell>
                    <TableCell>Grade</TableCell>
                    <TableCell align="right">Score</TableCell>
                    <TableCell align="right">Action</TableCell>
                    <TableCell align="right">Review</TableCell>
                    <TableCell align="right">Passing</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {history.data.slice(0, 12).map((h, i) => (
                    <TableRow key={i}>
                      <TableCell>{h.Date ? new Date(h.Date).toLocaleString() : ""}</TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={h.Grade}
                          color={GRADE_COLOR[h.Grade] || "default"}
                        />
                      </TableCell>
                      <TableCell align="right">{h.Score}</TableCell>
                      <TableCell align="right">{h.Fail}</TableCell>
                      <TableCell align="right">{h.Warn}</TableCell>
                      <TableCell align="right">{h.Pass}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CippButtonCard>
          </Grid>
        )}
      </Grid>

      {/* Schedule dialog */}
      <Dialog open={scheduleOpen} onClose={() => setScheduleOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Schedule {selected.label}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <CippFormComponent
              type="textField"
              name="scheduleName"
              label="Task Name"
              formControl={scheduleForm}
            />
            <CippFormComponent
              type="switch"
              name="allTenants"
              label="Run for all tenants (one report per client)"
              formControl={scheduleForm}
            />
            <CippFormComponent
              type="switch"
              name="connectWiseTicket"
              label="Create a ConnectWise ticket (posture summary)"
              formControl={scheduleForm}
            />
            <CippFormComponent
              type="autoComplete"
              name="recurrence"
              label="Recurrence"
              formControl={scheduleForm}
              options={[
                { label: "Once", value: "0" },
                { label: "Every 7 days", value: "7d" },
                { label: "Every 30 days", value: "30d" },
                { label: "Every 90 days", value: "90d" },
                { label: "Every 365 days", value: "365d" },
              ]}
              multiple={false}
            />
            <CippFormComponent
              type="autoComplete"
              name="postExecution"
              label="On completion"
              formControl={scheduleForm}
              options={[
                { label: "Email", value: "Email" },
                { label: "Webhook", value: "Webhook" },
                { label: "PSA", value: "PSA" },
              ]}
              multiple={true}
            />
            <Alert severity="info">
              Generated on this schedule for <strong>{tenantFilter || "the selected tenant"}</strong>{" "}
              (or every client if "all tenants" is enabled above). <strong>Email</strong> delivers
              the full HTML report as an attachment to your CIPP notification recipients. The{" "}
              <strong>ConnectWise ticket</strong> toggle opens a ticket with the posture summary
              (grade + action items). ("PSA" post-execution targets HaloPSA.)
            </Alert>
            <CippApiResults apiObject={scheduleCall} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setScheduleOpen(false)}>Close</Button>
          <Button
            variant="contained"
            onClick={handleSchedule}
            disabled={!tenantFilter || scheduleCall.isPending}
          >
            {scheduleCall.isPending ? "Scheduling…" : "Schedule"}
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
