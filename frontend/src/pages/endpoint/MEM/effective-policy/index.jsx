// Intune effective policy for one device (Aspendora fork, Vikunja CIPP-19).
// Read-only: shows every policy and assigned app that lands on the device, how it is targeted,
// the assignment filter and whether CIPP evaluated it, exclusions, device status, and Settings
// Catalog settings set by more than one applicable policy. Open with ?deviceId=<id> or pick a device.
import { useEffect } from "react";
import { useRouter } from "next/router";
import { useForm, useWatch } from "react-hook-form";
import { Alert, Container, Grid, Stack, Typography } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import CippTablePage from "../../../../components/CippComponents/CippTablePage";
import { CippFormComponent } from "../../../../components/CippComponents/CippFormComponent";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { ApiGetCall } from "../../../../api/ApiCall";
import { useSettings } from "../../../../hooks/use-settings";

const simpleColumns = [
  "Status",
  "PolicyType",
  "PolicyName",
  "Intent",
  "TargetedVia",
  "Filter",
  "FilterResult",
  "ExcludedBy",
  "DeviceStatus",
  "Notes",
];

const overlapColumns = ["Severity", "SettingDefinitionId", "PolicyCount", "Values"];

const filters = [
  { filterName: "Applies", value: [{ id: "Status", value: "Applies" }], type: "column" },
  {
    filterName: "Filter not evaluated",
    value: [{ id: "Status", value: "Applies unless filter excludes (not evaluated)" }],
    type: "column",
  },
  { filterName: "Excluded", value: [{ id: "Status", value: "Excluded" }], type: "column" },
  { filterName: "Filtered out", value: [{ id: "Status", value: "Filtered out" }], type: "column" },
];

const Page = () => {
  const router = useRouter();
  const tenant = useSettings().currentTenant;
  const formControl = useForm({ mode: "onChange", defaultValues: { device: null } });
  const picked = useWatch({ control: formControl.control, name: "device" });
  const queryDeviceId = typeof router.query.deviceId === "string" ? router.query.deviceId : "";
  const deviceId = picked?.value || queryDeviceId;
  const singleTenant = Boolean(tenant) && tenant !== "AllTenants";

  // A device picked from a different tenant is no longer valid once the tenant changes.
  const { setValue } = formControl;
  useEffect(() => {
    setValue("device", null);
  }, [tenant, setValue]);

  const report = ApiGetCall({
    url: "/api/ListIntuneEffectivePolicy",
    data: { tenantFilter: tenant, DeviceId: deviceId },
    queryKey: `ListIntuneEffectivePolicy-${tenant}-${deviceId}`,
    waiting: singleTenant && Boolean(deviceId),
  });

  const data = report.data ?? {};
  const rows = Array.isArray(data.Results) ? data.Results : [];
  const overlaps = Array.isArray(data.Overlaps) ? data.Overlaps : [];
  const summary = data.Summary ?? {};
  const device = data.Device ?? {};
  const errors = Array.isArray(data.Errors) ? data.Errors : [];
  const notes = Array.isArray(data.Notes) ? data.Notes : [];

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        <Grid size={{ xs: 12, md: 6 }}>
          <CippFormComponent
            type="autoComplete"
            name="device"
            label="Device"
            formControl={formControl}
            multiple={false}
            creatable={false}
            disabled={!singleTenant}
            api={{
              url: "/api/ListGraphRequest",
              data: {
                Endpoint: "deviceManagement/managedDevices",
                $select: "id,deviceName,userPrincipalName,operatingSystem",
                $top: 999,
              },
              queryKey: "ListManagedDevicesEffectivePolicy",
              dataKey: "Results",
              labelField: (d) =>
                `${d.deviceName}${d.userPrincipalName ? ` (${d.userPrincipalName})` : ""} - ${d.operatingSystem}`,
              valueField: "id",
              showRefresh: true,
            }}
          />
        </Grid>
        {!singleTenant && (
          <Grid size={12}>
            <Alert severity="info">Select a single tenant to look up a device.</Alert>
          </Grid>
        )}
        {singleTenant && !deviceId && (
          <Grid size={12}>
            <Alert severity="info">
              Pick a device to see which Intune policies and apps apply to it, and why. Nothing is changed.
            </Alert>
          </Grid>
        )}
        {report.isError && (
          <Grid size={12}>
            <Alert severity="error">
              {report.error?.response?.data?.Results ?? "The lookup failed."}
            </Alert>
          </Grid>
        )}
        {deviceId && singleTenant && (
          <>
            <Grid size={12}>
              <CippInfoBar
                isFetching={report.isFetching}
                data={[
                  {
                    icon: <CippIcons.Devices />,
                    data: device.DeviceName ?? "-",
                    name: `${device.OperatingSystem ?? ""} ${device.OsVersion ?? ""}`.trim() || "Device",
                    color: "secondary",
                  },
                  { icon: <CippIcons.CheckCircle />, data: summary.Applies ?? 0, name: "Applies", color: "success" },
                  {
                    icon: <CippIcons.Help />,
                    data: summary.FilterUnknown ?? 0,
                    name: "Filter not evaluated",
                    color: "info",
                  },
                  { icon: <CippIcons.Block />, data: summary.Excluded ?? 0, name: "Excluded", color: "warning" },
                  {
                    icon: <CippIcons.Warning />,
                    data: `${summary.Conflicts ?? 0} / ${summary.Overlaps ?? 0}`,
                    name: "Setting conflicts / overlaps",
                    color: "error",
                  },
                ]}
              />
            </Grid>
            <Grid size={12}>
              <Stack spacing={0.5}>
                <Typography variant="body2" color="text.secondary">
                  Primary user: {device.PrimaryUser || "none"} | Ownership: {device.Ownership || "unknown"}
                  {" | "}Group tag: {device.GroupTag || "none"} | Enrollment profile:{" "}
                  {device.EnrollmentProfile || "none"} | Device groups:{" "}
                  {Array.isArray(device.DeviceGroups) && device.DeviceGroups.length > 0
                    ? device.DeviceGroups.join(", ")
                    : "none"}
                  {" | "}Skipped (other platform): {summary.PlatformSkipped ?? 0}
                </Typography>
                {notes.map((n) => (
                  <Typography key={n} variant="caption" color="text.secondary">
                    {n}
                  </Typography>
                ))}
                {errors.map((e) => (
                  <Typography key={e} variant="caption" color="error">
                    {e}
                  </Typography>
                ))}
              </Stack>
            </Grid>
            <Grid size={12}>
              <CippTablePage
                title="Effective Policy"
                tenantInTitle={false}
                data={rows}
                isFetching={report.isFetching}
                // Rows come from the report query above; the table only needs its own cache key.
                queryKey={`ListIntuneEffectivePolicy-table-${tenant}-${deviceId}`}
                offCanvas={{
                  extendedInfoFields: [...simpleColumns, "FilterRule", "FilterMode", "Platform", "PolicyId"],
                }}
                simpleColumns={simpleColumns}
                filters={filters}
                maxHeightOffset="560px"
              />
            </Grid>
            <Grid size={12}>
              <CippTablePage
                title="Settings Catalog conflicts and overlaps"
                tenantInTitle={false}
                data={overlaps}
                isFetching={report.isFetching}
                queryKey={`ListIntuneEffectivePolicy-overlaps-${tenant}-${deviceId}`}
                offCanvas={{ extendedInfoFields: [...overlapColumns, "Policies"] }}
                simpleColumns={overlapColumns}
                maxHeightOffset="560px"
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
