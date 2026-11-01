// Sign-in failure explainer (Aspendora fork, Vikunja CIPP-10).
// /api/ListSignInExplanation reads one tenant's sign-in log live and changes nothing. The only write is the optional
// internal note on a ConnectWise ticket via /api/ExecSignInExplanationNote, which previews by default and refuses a
// ticket that belongs to a different company than the tenant's ConnectWise mapping.
// Opened with ?userPrincipalName=... (the "Explain sign-in failures" user action) it runs straight away.
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/router";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  FormControlLabel,
  Link,
  Stack,
  Switch,
  Typography,
} from "@mui/material";
import { Grid } from "@mui/system";
import { useForm } from "react-hook-form";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import CippFormComponent from "../../../../components/CippComponents/CippFormComponent";
import { CippFormUserSelector } from "../../../../components/CippComponents/CippFormUserSelector";
import CippButtonCard from "../../../../components/CippCards/CippButtonCard";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippApiResults } from "../../../../components/CippComponents/CippApiResults";
import { CippIcons } from "../../../../utils/icon-registry";
import { ApiPostCall } from "../../../../api/ApiCall";
import { useSettings } from "../../../../hooks/use-settings";
import { usePermissions } from "../../../../hooks/use-permissions";
import { getCippError } from "../../../../utils/get-cipp-error";

const outcomeColor = { Success: "success", Failure: "error", Interrupted: "warning" };
const flagColor = { error: "error", warning: "warning", info: "info" };
// Policies that did not take part are hidden by default; they are most of the list in a typical tenant.
const quietResults = ["notApplied", "reportOnlyNotApplied", "notEnabled"];
const yesNo = (v) => (v === true ? "yes" : v === false ? "no" : "unknown");

const SignInCard = ({ signIn, tenant, showQuiet }) => {
  const policies = (signIn.Policies ?? []).filter((p) => showQuiet || !quietResults.includes(p.Result));
  const device = signIn.Device ?? {};
  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
          <Chip size="small" label={signIn.Outcome} color={outcomeColor[signIn.Outcome] ?? "default"} />
          {signIn.ResolvedLater && <Chip size="small" variant="outlined" color="success" label="Followed by a success" />}
          <Typography variant="subtitle1">
            {signIn.Title}
            {signIn.ErrorCode ? ` (AADSTS${signIn.ErrorCode})` : ""}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {signIn.Time}
          </Typography>
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          {signIn.App}
          {signIn.ClientApp ? ` via ${signIn.ClientApp}` : ""} | {signIn.Location || "unknown location"}
          {signIn.IPAddress ? ` (${signIn.IPAddress})` : ""} | device {device.Name || "(none sent)"} {device.OS}{" "}
          {device.Browser}, compliant {yesNo(device.Compliant)}, managed {yesNo(device.Managed)}
          {device.TrustType ? `, ${device.TrustType}` : ""}
        </Typography>
        {Array.isArray(signIn.Flags) && signIn.Flags.length > 0 && (
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
            {signIn.Flags.map((f) => (
              <Chip key={f.Key} size="small" variant="outlined" color={flagColor[f.Severity] ?? "default"} label={f.Text} />
            ))}
          </Stack>
        )}
        <Typography variant="body2">{signIn.Explanation}</Typography>
        {Array.isArray(signIn.Details) && signIn.Details.length > 0 && (
          <Box component="ul" sx={{ mt: 1, mb: 0, pl: 3 }}>
            {signIn.Details.map((d, i) => (
              <li key={i}>
                <Typography variant="body2" color="text.secondary">
                  {d}
                </Typography>
              </li>
            ))}
          </Box>
        )}
        {signIn.Fix && (
          <Alert severity={signIn.Outcome === "Failure" && !signIn.ResolvedLater ? "info" : "success"} sx={{ mt: 1 }}>
            <strong>Fix: </strong>
            {signIn.Fix}
          </Alert>
        )}
        {signIn.FailureReason && (
          <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
            Microsoft: {signIn.FailureReason}
          </Typography>
        )}
        {policies.length > 0 && (
          <Box sx={{ mt: 1 }}>
            <CippDataTable
              title="Conditional Access policies evaluated"
              data={policies}
              queryKey={`SignInExplainer-${tenant}-${signIn.RequestId}-policies`}
              noCard={true}
              simple={false}
              simpleColumns={[
                "Name",
                "Result",
                "Effect",
                "Requires",
                "ConditionsMatched",
                "ConditionsNotMatched",
                "Locations",
                "State",
              ]}
            />
          </Box>
        )}
        <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap sx={{ mt: 1 }}>
          {signIn.Links?.EntraUserSignIns && (
            <Link href={signIn.Links.EntraUserSignIns} target="_blank" rel="noopener noreferrer" variant="body2">
              Entra sign-in log
            </Link>
          )}
          {signIn.Links?.ErrorLookup && (
            <Link href={signIn.Links.ErrorLookup} target="_blank" rel="noopener noreferrer" variant="body2">
              Microsoft error lookup
            </Link>
          )}
          {signIn.Links?.SignInDiagnostic && (
            <Link href={signIn.Links.SignInDiagnostic} target="_blank" rel="noopener noreferrer" variant="body2">
              How to run the Sign-in Diagnostic
            </Link>
          )}
          <Typography variant="caption" color="text.secondary">
            Correlation ID {signIn.CorrelationId} | Request ID {signIn.RequestId}
          </Typography>
        </Stack>
      </CardContent>
    </Card>
  );
};

const Page = () => {
  const tenant = useSettings().currentTenant;
  const singleTenant = Boolean(tenant) && tenant !== "AllTenants";
  const router = useRouter();
  const { checkPermissions } = usePermissions();
  const canPostNote = checkPermissions(["Identity.User.ReadWrite"]);
  const [bundle, setBundle] = useState(null);
  const [error, setError] = useState(null);
  const [notePreview, setNotePreview] = useState(null);
  const [copied, setCopied] = useState(false);
  const [showQuiet, setShowQuiet] = useState(false);
  const autoRan = useRef(false);
  const formControl = useForm({
    defaultValues: { Hours: 24, CorrelationId: "", IncludeNonInteractive: false, TicketId: "" },
    mode: "onChange",
  });

  const explain = ApiPostCall({ onResult: (result) => setBundle(result) });
  const note = ApiPostCall({ onResult: (result) => setNotePreview(result?.Note ?? null) });

  const run = () => {
    const v = formControl.getValues();
    const upn = v.UserPrincipalName?.value ?? v.UserPrincipalName ?? "";
    setBundle(null);
    setError(null);
    setNotePreview(null);
    setCopied(false);
    explain.mutate(
      {
        url: "/api/ListSignInExplanation",
        data: {
          tenantFilter: tenant,
          userPrincipalName: upn,
          correlationId: v.CorrelationId?.trim() ?? "",
          hours: Number(v.Hours) || 24,
          includeNonInteractive: Boolean(v.IncludeNonInteractive),
        },
      },
      { onError: (e) => setError(e?.response?.data?.Results ?? getCippError(e)) }
    );
  };

  // Prefill from a link and run once. The user action sends ?userId= (the backend accepts an object ID in place
  // of a UPN); ?userPrincipalName= also works for hand-made links.
  useEffect(() => {
    if (!router.isReady || autoRan.current || !singleTenant) return;
    const upn = router.query.userPrincipalName;
    const userId = router.query.userId;
    const value = typeof upn === "string" && upn ? upn : typeof userId === "string" && userId ? userId : null;
    if (value) {
      autoRan.current = true;
      formControl.setValue("UserPrincipalName", { label: value === upn ? value : `User ID ${value}`, value });
      run();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.isReady, router.query.userPrincipalName, router.query.userId, singleTenant]);

  const sendNote = (preview) => {
    const v = formControl.getValues();
    note.mutate({
      url: "/api/ExecSignInExplanationNote",
      data: { tenantFilter: tenant, TicketId: v.TicketId, Bundle: bundle, Preview: preview },
    });
  };

  const copySummary = async () => {
    try {
      await navigator.clipboard.writeText(bundle?.SummaryText ?? "");
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  if (!singleTenant) {
    return (
      <Box sx={{ px: 3, py: 2 }}>
        <Alert severity="info">Pick a single tenant to explain a user&apos;s sign-in failures.</Alert>
      </Box>
    );
  }

  const signIns = Array.isArray(bundle?.SignIns) ? bundle.SignIns : [];
  const errors = Array.isArray(bundle?.Errors) ? bundle.Errors : [];
  const byError = Array.isArray(bundle?.ByError) ? bundle.ByError : [];
  const hasInput = Boolean(formControl.watch("UserPrincipalName")) || Boolean(formControl.watch("CorrelationId"));
  const unresolved = signIns.some((s) => s.Outcome !== "Success" && !s.ResolvedLater);

  return (
    <Stack spacing={2} sx={{ px: 3, py: 2 }}>
      <CippButtonCard
        title="Why can't this user sign in?"
        CardButton={
          <Button variant="contained" startIcon={<CippIcons.Search />} disabled={explain.isPending || !hasInput} onClick={run}>
            {explain.isPending ? "Reading sign-ins..." : "Explain"}
          </Button>
        }
      >
        <Grid container spacing={1.5}>
          <Grid size={{ xs: 12, md: 5 }}>
            <CippFormUserSelector
              formControl={formControl}
              name="UserPrincipalName"
              label="User (pick or type a UPN)"
              multiple={false}
              valueField="userPrincipalName"
              creatable={true}
              freeSolo
            />
          </Grid>
          <Grid size={{ xs: 12, md: 2 }}>
            <CippFormComponent type="number" name="Hours" label="Hours back" helperText="Default 24, max 720" formControl={formControl} />
          </Grid>
          <Grid size={{ xs: 12, md: 5 }}>
            <CippFormComponent
              type="textField"
              name="CorrelationId"
              label="Or a correlation / request ID"
              helperText="From the user's error screen; searches the last 30 days"
              formControl={formControl}
            />
          </Grid>
          <Grid size={12}>
            <CippFormComponent
              type="switch"
              name="IncludeNonInteractive"
              label="Include non-interactive sign-ins (apps refreshing in the background)"
              formControl={formControl}
            />
          </Grid>
        </Grid>
        <Typography variant="caption" color="text.secondary">
          Read-only. Reads the Entra sign-in log (needs Entra ID P1), keeps failures and interrupted sign-ins plus the
          latest success, and explains each: error code, every Conditional Access policy and its result, MFA source
          (Conditional Access, per-user MFA, security defaults), device, legacy authentication and risk. Times are US
          Central with UTC alongside.
        </Typography>
      </CippButtonCard>

      {error && <Alert severity="error">{String(error)}</Alert>}

      {bundle && (
        <>
          <Alert severity={bundle.LicenseRequired ? "warning" : unresolved ? "error" : "success"}>
            <Typography variant="subtitle2">{bundle.Headline}</Typography>
            <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
              {bundle.UserPrincipalName || bundle.CorrelationId} | {bundle.WindowStart?.Display} to{" "}
              {bundle.WindowEnd?.Display}
              {bundle.Counts
                ? ` | ${bundle.Counts.Total} sign-ins: ${bundle.Counts.Failures} failed, ${bundle.Counts.Interrupts} interrupted, ${bundle.Counts.Successes} succeeded`
                : ""}
              {bundle.LatestSuccess ? ` | latest success ${bundle.LatestSuccess}` : ""}
              {bundle.Truncated ? " | only the newest 999 were read" : ""}
            </Typography>
            {bundle.User && (
              <Typography variant="caption" display="block">
                Account {bundle.User.AccountEnabled === false ? "DISABLED" : "enabled"} | per-user MFA{" "}
                {bundle.User.PerUserMfaState || "unknown"} | security defaults{" "}
                {bundle.SecurityDefaultsEnabled === true ? "on" : bundle.SecurityDefaultsEnabled === false ? "off" : "unknown"}
                {bundle.User.Synced ? " | synced from on-premises AD" : ""}
              </Typography>
            )}
          </Alert>

          {errors.length > 0 && <Alert severity="warning">Some data could not be read: {errors.join("; ")}</Alert>}
          {bundle.PasswordAttempts && (
            <Alert severity={bundle.PasswordAttempts.LikelyAttack ? "warning" : "info"}>{bundle.PasswordAttempts.Summary}</Alert>
          )}

          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
            <Button startIcon={<CippIcons.ContentCopy />} onClick={copySummary}>
              {copied ? "Copied" : "Copy summary"}
            </Button>
            <FormControlLabel
              control={<Switch checked={showQuiet} onChange={(e) => setShowQuiet(e.target.checked)} />}
              label="Show policies that did not apply"
            />
          </Stack>

          {byError.length > 1 && (
            <CippDataTable
              title="All failures in the window, by error"
              data={byError}
              queryKey={`SignInExplainer-${tenant}-byerror`}
              simpleColumns={["ErrorCode", "Title", "Outcome", "Count", "LastSeen"]}
            />
          )}

          {signIns.map((s) => (
            <SignInCard key={s.RequestId} signIn={s} tenant={tenant} showQuiet={showQuiet} />
          ))}

          {canPostNote && !bundle.LicenseRequired && (
            <CippButtonCard title="Post to a ConnectWise ticket">
              <Grid container spacing={1.5} alignItems="center">
                <Grid size={{ xs: 12, md: 4 }}>
                  <CippFormComponent type="textField" name="TicketId" label="ConnectWise ticket number" formControl={formControl} />
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
                emailed. Refused if the tenant has no ConnectWise company mapping or the ticket belongs to another company.
              </Typography>
              <CippApiResults apiObject={note} />
              {notePreview && (
                <Box
                  component="pre"
                  sx={{ mt: 1, p: 1.5, whiteSpace: "pre-wrap", fontSize: 12, bgcolor: "action.hover", borderRadius: 1 }}
                >
                  {notePreview}
                </Box>
              )}
            </CippButtonCard>
          )}
        </>
      )}
    </Stack>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
