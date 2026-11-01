// Mail delivery triage (Aspendora fork, Vikunja CIPP-38).
// Runs /api/ListMailTriage for one recipient (read-only, nine checks) and can post the evidence bundle as an
// internal note on an existing ConnectWise ticket via /api/ExecMailTriageNote.
import { useState } from "react";
import { Alert, Box, Button, Card, CardContent, Chip, Stack, Typography } from "@mui/material";
import { Grid } from "@mui/system";
import { useForm } from "react-hook-form";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import CippFormComponent from "../../../../components/CippComponents/CippFormComponent";
import CippButtonCard from "../../../../components/CippCards/CippButtonCard";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippApiResults } from "../../../../components/CippComponents/CippApiResults";
import { CippIcons } from "../../../../utils/icon-registry";
import { ApiPostCall } from "../../../../api/ApiCall";
import { useSettings } from "../../../../hooks/use-settings";
import { getCippError } from "../../../../utils/get-cipp-error";

const statusColor = { OK: "success", Problem: "error", Unknown: "warning" };
const overallSeverity = { OK: "success", Problem: "error", Unknown: "warning" };

// Evidence is either a list of rows or a single object; show both as a table.
const evidenceRows = (evidence) => {
  if (!evidence) return [];
  if (Array.isArray(evidence)) return evidence;
  return Object.entries(evidence)
    .filter(([, v]) => v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && v.length === 0))
    .map(([Property, v]) => ({
      Property,
      Value: Array.isArray(v)
        ? v.map((i) => (typeof i === "object" ? Object.values(i).join(" / ") : i)).join("; ")
        : typeof v === "object"
          ? JSON.stringify(v)
          : String(v),
    }));
};

const StepCard = ({ step, tenant }) => {
  const rows = evidenceRows(step.Evidence);
  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
          <Chip size="small" label={step.Status} color={statusColor[step.Status] ?? "default"} />
          <Typography variant="subtitle1">
            {step.Order}. {step.Title}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {step.DurationS}s
          </Typography>
        </Stack>
        <Typography variant="body2">{step.Summary}</Typography>
        {Array.isArray(step.Findings) && step.Findings.length > 0 && (
          <Box component="ul" sx={{ mt: 1, mb: 0, pl: 3 }}>
            {step.Findings.map((f, i) => (
              <li key={i}>
                <Typography variant="body2" color="text.secondary">
                  {f}
                </Typography>
              </li>
            ))}
          </Box>
        )}
        {rows.length > 0 && (
          <Box sx={{ mt: 1 }}>
            <CippDataTable
              title="Evidence"
              data={rows}
              queryKey={`MailTriage-${tenant}-${step.Key}`}
              noCard={true}
              simple={false}
            />
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

const Page = () => {
  const tenant = useSettings().currentTenant;
  const singleTenant = Boolean(tenant) && tenant !== "AllTenants";
  const [bundle, setBundle] = useState(null);
  const [error, setError] = useState(null);
  const [notePreview, setNotePreview] = useState(null);
  const formControl = useForm({ defaultValues: { Hours: 48, Sender: "", TicketId: "" }, mode: "onChange" });

  const triage = ApiPostCall({ onResult: (result) => setBundle(result) });
  const note = ApiPostCall({ onResult: (result) => setNotePreview(result?.Note ?? null) });

  const run = () => {
    const v = formControl.getValues();
    const recipient = v.Recipient?.value ?? v.Recipient;
    setBundle(null);
    setError(null);
    setNotePreview(null);
    triage.mutate(
      {
        url: "/api/ListMailTriage",
        data: { tenantFilter: tenant, Recipient: recipient, Sender: v.Sender, Hours: Number(v.Hours) || 48 },
      },
      { onError: (e) => setError(e?.response?.data?.Results ?? getCippError(e)) }
    );
  };

  const sendNote = (preview) => {
    const v = formControl.getValues();
    note.mutate({
      url: "/api/ExecMailTriageNote",
      data: { tenantFilter: tenant, TicketId: v.TicketId, Bundle: bundle, Preview: preview },
    });
  };

  if (!singleTenant) {
    return (
      <Box sx={{ px: 3, py: 2 }}>
        <Alert severity="info">Pick a single tenant to triage a mail delivery problem.</Alert>
      </Box>
    );
  }

  const steps = Array.isArray(bundle?.Steps) ? bundle.Steps : [];
  const counts = (s) => steps.filter((x) => x.Status === s).length;

  return (
    <Stack spacing={2} sx={{ px: 3, py: 2 }}>
      <CippButtonCard
        title="Mail not received or delayed"
        CardButton={
          <Button
            variant="contained"
            startIcon={<CippIcons.Search />}
            disabled={triage.isPending || !formControl.watch("Recipient")}
            onClick={run}
          >
            {triage.isPending ? "Checking..." : "Run triage"}
          </Button>
        }
      >
        <Grid container spacing={1.5}>
          <Grid size={{ xs: 12, md: 5 }}>
            <CippFormComponent
              type="autoComplete"
              freeSolo
              creatable={true}
              multiple={false}
              name="Recipient"
              label="Recipient (who is missing the mail)"
              placeholder="Type an address or pick a mailbox"
              api={{
                url: "/api/ListMailboxes",
                labelField: (option) => option.UPN,
                valueField: "UPN",
                queryKey: `ListMailboxes-${tenant}`,
                manualSearch: true,
                searchParam: "Anr",
                data: { Minimal: true },
              }}
              formControl={formControl}
              required={true}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 5 }}>
            <CippFormComponent
              type="textField"
              name="Sender"
              label="Sender address (optional)"
              helperText="Leave empty to look at all mail to the recipient"
              formControl={formControl}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 2 }}>
            <CippFormComponent type="number" name="Hours" label="Hours back" helperText="Default 48, max 240" formControl={formControl} />
          </Grid>
        </Grid>
        <Typography variant="caption" color="text.secondary">
          Read-only. Checks, in order: service health, message trace, quarantine, mail flow rules, inbox rules (including
          hidden), sender restrictions and forwarding, mailbox quota, Tenant Allow/Block List and the user&apos;s Blocked
          Senders, and sign-in state. Times are US Central with UTC alongside.
        </Typography>
      </CippButtonCard>

      {error && <Alert severity="error">{String(error)}</Alert>}

      {bundle && (
        <>
          <Alert severity={overallSeverity[bundle.Overall] ?? "info"}>
            <Typography variant="subtitle2">
              {bundle.Overall}: {counts("Problem")} problem, {counts("OK")} OK, {counts("Unknown")} could not check
            </Typography>
            <Typography variant="body2">{bundle.Summary}</Typography>
            <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
              {bundle.Recipient}
              {bundle.Sender ? ` from ${bundle.Sender}` : ""} | {bundle.WindowStart?.Display} to {bundle.WindowEnd?.Display} | run{" "}
              {bundle.GeneratedAt?.Display}
            </Typography>
          </Alert>

          {steps.map((step) => (
            <StepCard key={step.Key} step={step} tenant={tenant} />
          ))}

          <CippButtonCard title="Post to a ConnectWise ticket">
            <Grid container spacing={1.5} alignItems="center">
              <Grid size={{ xs: 12, md: 4 }}>
                <CippFormComponent
                  type="textField"
                  name="TicketId"
                  label="ConnectWise ticket number"
                  formControl={formControl}
                />
              </Grid>
              <Grid size={{ xs: 12, md: 8 }}>
                <Stack direction="row" spacing={1}>
                  <Button startIcon={<CippIcons.Visibility />} disabled={note.isPending} onClick={() => sendNote(true)}>
                    Preview note
                  </Button>
                  <Button
                    variant="contained"
                    startIcon={<CippIcons.Send />}
                    disabled={note.isPending || !formControl.watch("TicketId")}
                    onClick={() => sendNote(false)}
                  >
                    Post as internal note
                  </Button>
                </Stack>
              </Grid>
            </Grid>
            <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
              Posted to the ticket&apos;s Internal Analysis tab with ConnectWise notifications off, so the client is not
              emailed. Refused if the ticket belongs to a different company than this tenant&apos;s ConnectWise mapping.
            </Typography>
            <CippApiResults apiObject={note} />
            {notePreview && (
              <Box component="pre" sx={{ mt: 1, p: 1.5, whiteSpace: "pre-wrap", fontSize: 12, bgcolor: "action.hover", borderRadius: 1 }}>
                {notePreview}
              </Box>
            )}
          </CippButtonCard>
        </>
      )}
    </Stack>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
