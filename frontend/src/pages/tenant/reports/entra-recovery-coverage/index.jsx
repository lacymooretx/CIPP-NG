// Entra recovery coverage (Aspendora fork, Vikunja CIPP-17).
// /api/ListEntraRecoveryCoverage is read only: Entra Backup and Recovery snapshot status, CIPP scheduled backup
// coverage and gaps, and soft-deleted Conditional Access objects. Nothing here backs up or restores anything.
// Restoring a deleted user, group, app or service principal is the existing Deleted Items page; scheduling a
// backup is the existing Backup Tasks wizard. Both are linked rather than duplicated.
import { Alert, Button, Container, Grid, Stack } from "@mui/material";
import Link from "next/link";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { useSettings } from "../../../../hooks/use-settings";
import { ApiGetCall } from "../../../../api/ApiCall";

const Page = () => {
  const tenant = useSettings().currentTenant || "AllTenants";

  const report = ApiGetCall({
    url: "/api/ListEntraRecoveryCoverage",
    data: { tenantFilter: tenant },
    queryKey: `EntraRecoveryCoverage-${tenant}`,
  });

  const summary = report.data?.Summary;
  const rows = Array.isArray(report.data?.Rows) ? report.data.Rows : [];
  const errors = Array.isArray(report.data?.Errors) ? report.data.Errors : [];
  const limits = Array.isArray(report.data?.KnownLimits) ? report.data.KnownLimits : [];
  const maxAge = report.data?.MaxBackupAgeDays ?? 2;

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {errors.length > 0 && (
          <Grid size={12}>
            <Alert severity="warning">Some data could not be read: {errors.join("; ")}</Alert>
          </Grid>
        )}
        {summary && summary.NativeNoPermission > 0 && (
          <Grid size={12}>
            <Alert severity="info">
              {summary.NativeNoPermission} tenant(s) answered "No permission" for Entra Backup and Recovery
              snapshots. The CIPP app needs the Microsoft Graph application permission EntraBackup.Read.All
              (added to the CIPP-SAM app and consented through a CPV refresh). Until then, check snapshots in the
              Entra admin center under Backup and recovery.
            </Alert>
          </Grid>
        )}
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: <CippIcons.Warning />,
                data: summary?.CippGap ?? "-",
                name: `No current CIPP backup (none scheduled, none taken, or older than ${maxAge} days)`,
                color: summary?.CippGap ? "error" : "success",
              },
              {
                icon: <CippIcons.Backup />,
                data: summary?.CippPartial ?? "-",
                name: "CIPP backup missing Conditional Access or users/groups",
                color: summary?.CippPartial ? "warning" : "success",
              },
              {
                icon: <CippIcons.CheckCircle />,
                data: summary ? `${summary.CippCovered} of ${summary.Tenants}` : "-",
                name: "CIPP backup covered",
                color: "info",
              },
              {
                icon: <CippIcons.History />,
                data: summary ? `${summary.NativeAvailable} of ${summary.NativeEligible}` : "-",
                name: "Entra snapshots readable / tenants with Entra ID P1 or P2",
                color: "info",
              },
              {
                icon: <CippIcons.RestoreFromTrash />,
                data: summary
                  ? `${summary.SoftDeletedCaPolicies} / ${summary.SoftDeletedNamedLocations}`
                  : "-",
                name: "Soft-deleted CA policies / named locations (restorable 30 days)",
                color:
                  summary?.SoftDeletedCaPolicies || summary?.SoftDeletedNamedLocations
                    ? "warning"
                    : "info",
              },
            ]}
          />
        </Grid>
        {limits.length > 0 && (
          <Grid size={12}>
            <Alert severity="info">
              <strong>What no backup here covers:</strong> {limits.join(" ")}
            </Alert>
          </Grid>
        )}
        <Grid size={12}>
          <CippDataTable
            title={`Entra recovery coverage - ${tenant}`}
            data={rows}
            isFetching={report.isFetching}
            queryKey={`EntraRecoveryCoverage-${tenant}-table`}
            simpleColumns={[
              "tenant",
              "cippStatus",
              "gaps",
              "cippLastBackup",
              "cippLastBackupAgeDays",
              "cippComponents",
              "cippLastBackupItems",
              "cippTasks",
              "entraLicence",
              "nativeStatus",
              "nativeSnapshotCount",
              "nativeLatestSnapshot",
              "nativeWindowDays",
              "softDeletedCaPolicies",
              "softDeletedNamedLocations",
            ]}
            cardButton={
              <Stack direction="row" spacing={1}>
                <Button
                  component={Link}
                  href="/tenant/backup/backup-wizard/add"
                  startIcon={<CippIcons.Backup />}
                >
                  Schedule CIPP Backup
                </Button>
                <Button
                  component={Link}
                  href="/identity/administration/deleted-items"
                  startIcon={<CippIcons.RestoreFromTrash />}
                >
                  Restore Deleted Object
                </Button>
                <Button
                  component="a"
                  href="https://entra.microsoft.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  startIcon={<CippIcons.OpenInNew />}
                >
                  Entra Backup and Recovery
                </Button>
                <Button
                  startIcon={<CippIcons.Refresh />}
                  disabled={report.isFetching}
                  onClick={() => report.refetch()}
                >
                  {report.isFetching ? "Reading..." : "Refresh"}
                </Button>
              </Stack>
            }
          />
        </Grid>
      </Grid>
    </Container>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
