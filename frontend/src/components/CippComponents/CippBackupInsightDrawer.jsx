// Aspendora fork addition (Vikunja CIPP-23): Verify / Compare / Restore preview for tenant backups.
import { useEffect, useMemo, useState } from "react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  AlertTitle,
  Autocomplete,
  Box,
  Button,
  Chip,
  CircularProgress,
  Drawer,
  FormControlLabel,
  IconButton,
  MenuItem,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { CippIcons } from "../../utils/icon-registry";
import { ApiPostCall } from "../../api/ApiCall";

export const BACKUP_COMPONENT_OPTIONS = [
  { value: "ca", label: "Conditional Access" },
  { value: "intuneconfig", label: "Intune Configuration" },
  { value: "intunecompliance", label: "Intune Compliance" },
  { value: "intuneprotection", label: "Intune Protection" },
  { value: "users", label: "Users" },
  { value: "groups", label: "Groups" },
  { value: "antispam", label: "Anti-Spam" },
  { value: "antiphishing", label: "Anti-Phishing" },
  { value: "teamsvoice", label: "Teams Phone Numbers" },
  { value: "CippWebhookAlerts", label: "CIPP Webhook Alerts" },
  { value: "CippScriptedAlerts", label: "CIPP Scripted Alerts" },
  { value: "CippCustomVariables", label: "Custom Variables" },
];
const DEFAULT_PREVIEW_TYPES = ["ca", "intuneconfig", "intunecompliance", "intuneprotection"];
const componentLabel = (value) =>
  BACKUP_COMPONENT_OPTIONS.find((o) => o.value === value)?.label || value;

export const formatBackupName = (name) => {
  const match = name?.match(/.*_(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})/);
  return match ? `${match[1]} @ ${match[2]}:${match[3]}` : name;
};

const STATUS_COLORS = {
  Verified: "success",
  "Unverified (pre-hash)": "default",
  CountMismatch: "warning",
  Missing: "error",
  Corrupt: "error",
  Added: "success",
  Removed: "error",
  Changed: "warning",
  Create: "success",
  Identical: "default",
  Conflict: "warning",
  Unparsed: "error",
};
const StatusChip = ({ status, size = "small" }) => (
  <Chip label={status} size={size} color={STATUS_COLORS[status] || "default"} variant="outlined" />
);

const errorText = (apiCall) =>
  apiCall.error?.response?.data?.Results || apiCall.error?.message || "Request failed";

const ChangesTable = ({ changes }) => {
  if (!changes?.length) return null;
  const show = (v) => (v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
  return (
    <Table size="small">
      <TableHead>
        <TableRow>
          <TableCell>Property</TableCell>
          <TableCell>Change</TableCell>
          <TableCell>Before</TableCell>
          <TableCell>After</TableCell>
        </TableRow>
      </TableHead>
      <TableBody>
        {changes.map((c, i) => (
          <TableRow key={`${c.Path}-${i}`}>
            <TableCell sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>{c.Path}</TableCell>
            <TableCell>{c.Change}</TableCell>
            <TableCell sx={{ fontFamily: "monospace", wordBreak: "break-all", maxWidth: 280 }}>
              {show(c.Before)}
            </TableCell>
            <TableCell sx={{ fontFamily: "monospace", wordBreak: "break-all", maxWidth: 280 }}>
              {show(c.After)}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
};

const ObjectList = ({ objects, statusField, extra }) => {
  if (!objects?.length) {
    return <Alert severity="info">No objects to show.</Alert>;
  }
  return (
    <Stack spacing={1}>
      {objects.map((o) => (
        <Accordion key={`${o.Type}-${o.Key}`} disableGutters variant="outlined">
          <AccordionSummary expandIcon={<CippIcons.ExpandMore />}>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <StatusChip status={o[statusField]} />
              <Chip label={componentLabel(o.Type)} size="small" />
              <Typography variant="body2" sx={{ fontWeight: 600 }}>
                {o.Name}
              </Typography>
              {o.Changes?.length > 0 && (
                <Typography variant="caption" color="text.secondary">
                  {o.Changes.length} change{o.Changes.length === 1 ? "" : "s"}
                </Typography>
              )}
            </Stack>
          </AccordionSummary>
          <AccordionDetails>
            {extra && extra(o)}
            {o.Changes?.length > 0 ? (
              <ChangesTable changes={o.Changes} />
            ) : (
              <Typography variant="body2" color="text.secondary">
                No property-level differences.
              </Typography>
            )}
          </AccordionDetails>
        </Accordion>
      ))}
    </Stack>
  );
};

const VerifyPanel = ({ backup }) => {
  const verify = ApiPostCall({});
  useEffect(() => {
    verify.mutate({
      url: "/api/ExecBackupVerify",
      data: { BackupName: backup.name, tenantFilter: backup.tenantSource, Type: "Scheduled" },
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [backup.name]);

  if (verify.isPending) return <CircularProgress />;
  if (verify.isError) return <Alert severity="error">{errorText(verify)}</Alert>;
  const r = verify.data?.data?.Results;
  if (!r) return null;
  return (
    <Stack spacing={2}>
      <Alert
        severity={
          r.Status === "Verified" ? "success" : r.Status === "Unverified (pre-hash)" ? "info" : r.Status === "CountMismatch" ? "warning" : "error"
        }
      >
        <AlertTitle>{r.Status}</AlertTitle>
        {r.Detail}
        {r.Issues?.length > 0 && (
          <ul style={{ margin: "8px 0 0 0" }}>
            {r.Issues.map((i) => (
              <li key={i}>{i}</li>
            ))}
          </ul>
        )}
      </Alert>
      {r.BackupSha256Actual && (
        <Typography variant="caption" sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
          SHA-256: {r.BackupSha256Actual}
        </Typography>
      )}
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Component</TableCell>
            <TableCell align="right">Recorded</TableCell>
            <TableCell align="right">Found</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Problems</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {(r.Types || []).map((t) => (
            <TableRow key={t.Type}>
              <TableCell>{componentLabel(t.Type)}</TableCell>
              <TableCell align="right">{t.ExpectedCount ?? "-"}</TableCell>
              <TableCell align="right">{t.ActualCount}</TableCell>
              <TableCell>
                <StatusChip status={t.Status} />
              </TableCell>
              <TableCell sx={{ fontSize: "0.75rem", wordBreak: "break-all" }}>
                {[
                  t.Missing?.length ? `Missing: ${t.Missing.join(", ")}` : null,
                  t.Corrupt?.length ? `Corrupt: ${t.Corrupt.join(", ")}` : null,
                  t.Unexpected?.length ? `Unexpected: ${t.Unexpected.join(", ")}` : null,
                ]
                  .filter(Boolean)
                  .join(" | ")}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Stack>
  );
};

const ComparePanel = ({ backup, backups }) => {
  const candidates = useMemo(
    () => (backups || []).filter((b) => b.name !== backup.name && b.tenantSource === backup.tenantSource),
    [backups, backup],
  );
  // Default to the newest backup older than this one, else the first other backup.
  const defaultOther = useMemo(() => {
    const older = candidates.filter((b) => new Date(b.timestamp) < new Date(backup.timestamp));
    return (older[0] || candidates[0])?.name || "";
  }, [candidates, backup]);
  const [other, setOther] = useState(defaultOther);
  const [includeAssignments, setIncludeAssignments] = useState(false);
  const diff = ApiPostCall({});
  useEffect(() => setOther(defaultOther), [defaultOther]);

  const run = () => {
    const otherBackup = candidates.find((b) => b.name === other);
    // Base is the older backup so "Added" means added since then.
    const otherIsOlder = otherBackup && new Date(otherBackup.timestamp) < new Date(backup.timestamp);
    diff.mutate({
      url: "/api/ExecBackupDiff",
      data: {
        BackupA: otherIsOlder ? other : backup.name,
        BackupB: otherIsOlder ? backup.name : other,
        tenantFilter: backup.tenantSource,
        IncludeAssignments: includeAssignments,
      },
    });
  };
  const r = diff.data?.data?.Results;

  if (candidates.length === 0) {
    return <Alert severity="info">There is no other backup of this tenant to compare with.</Alert>;
  }
  return (
    <Stack spacing={2}>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }}>
        <TextField
          select
          size="small"
          label="Compare with"
          value={other}
          onChange={(e) => setOther(e.target.value)}
          sx={{ minWidth: 240 }}
        >
          {candidates.map((b) => (
            <MenuItem key={b.name} value={b.name}>
              {formatBackupName(b.name)}
            </MenuItem>
          ))}
        </TextField>
        <FormControlLabel
          control={<Switch checked={includeAssignments} onChange={(e) => setIncludeAssignments(e.target.checked)} />}
          label="Include assignments"
        />
        <Button variant="contained" onClick={run} disabled={!other || diff.isPending} startIcon={<CippIcons.CompareArrows />}>
          {diff.isPending ? "Comparing..." : "Compare"}
        </Button>
      </Stack>
      {diff.isError && <Alert severity="error">{errorText(diff)}</Alert>}
      {r && (
        <>
          <Typography variant="body2" color="text.secondary">
            {formatBackupName(r.BackupA)} → {formatBackupName(r.BackupB)}. Ignores ids, timestamps, versions,
            @odata annotations{r.IncludeAssignments ? "" : " and assignments"}.
          </Typography>
          <Stack direction="row" spacing={1}>
            <Chip label={`${r.Summary.Added} added`} color="success" size="small" />
            <Chip label={`${r.Summary.Removed} removed`} color="error" size="small" />
            <Chip label={`${r.Summary.Changed} changed`} color="warning" size="small" />
            <Chip label={`${r.Summary.Unchanged} unchanged`} size="small" />
          </Stack>
          <ObjectList objects={r.Objects} statusField="Status" />
        </>
      )}
    </Stack>
  );
};

const PreviewPanel = ({ backup }) => {
  const [types, setTypes] = useState(
    BACKUP_COMPONENT_OPTIONS.filter((o) => DEFAULT_PREVIEW_TYPES.includes(o.value)),
  );
  const [safeMode, setSafeMode] = useState(true);
  const [overwrite, setOverwrite] = useState(false);
  const preview = ApiPostCall({});
  const run = () =>
    preview.mutate({
      url: "/api/ExecBackupRestorePreview",
      data: {
        BackupName: backup.name,
        tenantFilter: backup.tenantSource,
        Types: types.map((t) => t.value),
        SafeMode: safeMode,
        Overwrite: overwrite,
      },
    });
  const r = preview.data?.data?.Results;

  return (
    <Stack spacing={2}>
      <Alert severity="info">
        Reads the tenant as it is now and shows what a restore of this backup would do. Nothing is written.
        Large components (Intune configuration, users) can take a minute to read.
      </Alert>
      <Autocomplete
        multiple
        size="small"
        options={BACKUP_COMPONENT_OPTIONS}
        value={types}
        onChange={(_, v) => setTypes(v)}
        isOptionEqualToValue={(o, v) => o.value === v.value}
        getOptionLabel={(o) => o.label}
        renderInput={(params) => <TextField {...params} label="Components" />}
      />
      <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }}>
        <FormControlLabel
          control={<Switch checked={safeMode} onChange={(e) => setSafeMode(e.target.checked)} />}
          label="Safe restore-as-new"
        />
        {!safeMode && (
          <FormControlLabel
            control={<Switch checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} />}
            label="Overwrite existing entries"
          />
        )}
        <Button
          variant="contained"
          onClick={run}
          disabled={preview.isPending || types.length === 0}
          startIcon={<CippIcons.FactCheck />}
        >
          {preview.isPending ? "Reading tenant..." : "Preview restore"}
        </Button>
      </Stack>
      {preview.isError && <Alert severity="error">{errorText(preview)}</Alert>}
      {r && (
        <>
          <Alert severity={r.Integrity?.Status === "Verified" ? "success" : r.Integrity?.Status === "Unverified (pre-hash)" ? "info" : "warning"}>
            Backup integrity: <strong>{r.Integrity?.Status}</strong> - {r.Integrity?.Detail}
          </Alert>
          {r.ReadErrors?.length > 0 && (
            <Alert severity="warning">
              <AlertTitle>Some components could not be read from the tenant and are not previewed</AlertTitle>
              {r.ReadErrors.join(" ")}
            </Alert>
          )}
          {r.NotPreviewed?.length > 0 && (
            <Alert severity="info">Not previewable: {r.NotPreviewed.map(componentLabel).join(", ")}</Alert>
          )}
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            <Chip label={`${r.Summary.Create} new`} color="success" size="small" />
            <Chip label={`${r.Summary.Conflict} conflicting`} color="warning" size="small" />
            <Chip label={`${r.Summary.Identical} identical`} size="small" />
            {r.Summary.Unparsed > 0 && <Chip label={`${r.Summary.Unparsed} unreadable`} color="error" size="small" />}
            {r.SafeMode && <Chip label={`${r.Summary.NewCopies} copies would be created`} color="primary" size="small" />}
          </Stack>
          <ObjectList
            objects={r.Objects}
            statusField="Classification"
            extra={(o) => (
              <Box sx={{ mb: 1 }}>
                <Typography variant="body2">
                  <strong>Restore would:</strong> {o.Action}
                </Typography>
                {o.Classification === "Conflict" && (
                  <Typography variant="caption" color="text.secondary">
                    Before = current tenant value, After = value in the backup.
                  </Typography>
                )}
              </Box>
            )}
          />
        </>
      )}
    </Stack>
  );
};

const TITLES = { verify: "Verify Backup", compare: "Compare Backups", preview: "Restore Preview" };

export const CippBackupInsightDrawer = ({ open, mode, backup, backups, onClose }) => (
  <Drawer
    anchor="right"
    open={open}
    onClose={onClose}
    PaperProps={{ sx: { width: { xs: "100%", sm: "80%", md: "60%" } } }}
  >
    <Box sx={{ p: 3 }}>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 3 }}>
        <Box>
          <Typography variant="h5">{TITLES[mode]}</Typography>
          {backup && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
              {formatBackupName(backup.name)} ({backup.tenantSource})
            </Typography>
          )}
        </Box>
        <IconButton onClick={onClose}>
          <CippIcons.Close />
        </IconButton>
      </Stack>
      {open && backup && mode === "verify" && <VerifyPanel backup={backup} />}
      {open && backup && mode === "compare" && <ComparePanel backup={backup} backups={backups} />}
      {open && backup && mode === "preview" && <PreviewPanel backup={backup} />}
    </Box>
  </Drawer>
);

export default CippBackupInsightDrawer;
