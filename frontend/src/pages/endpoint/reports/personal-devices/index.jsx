// Personal devices (Aspendora fork, Vikunja CIPP-21).
// /api/ListPersonalDevices is read only: a single tenant is read live, AllTenants comes from the CIPP reporting cache.
// The controls that stop new BYOD enrollments are the DefaultPlatformRestrictions and MDMEnrollmentDuringRegistration
// standards; this page only shows their current state next to the devices that are already enrolled.
import { Alert, Button, Container, Grid } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { useSettings } from "../../../../hooks/use-settings";
import { ApiGetCall } from "../../../../api/ApiCall";

// null means the control could not be read (no Intune licence, missing permission, or not cached yet).
const blockedText = (value) => (value === true ? "Blocked" : value === false ? "Allowed" : "Unknown");
const blockedColor = (value) => (value === true ? "success" : value === false ? "warning" : "info");

const Page = () => {
  const tenant = useSettings().currentTenant;
  const allTenants = !tenant || tenant === "AllTenants";

  const report = ApiGetCall({
    url: "/api/ListPersonalDevices",
    data: { tenantFilter: allTenants ? "AllTenants" : tenant },
    queryKey: `PersonalDevices-${tenant}`,
  });

  const tenants = Array.isArray(report.data?.Tenants) ? report.data.Tenants : [];
  const devices = Array.isArray(report.data?.Devices) ? report.data.Devices : [];
  const errors = Array.isArray(report.data?.Errors) ? report.data.Errors : [];
  const one = !allTenants ? tenants[0] : null;
  const total = (key) => tenants.reduce((sum, row) => sum + (Number(row?.[key]) || 0), 0);

  const deviceColumns = [
    ...(allTenants ? ["Tenant"] : []),
    "deviceName",
    "operatingSystem",
    "osVersion",
    "userPrincipalName",
    "enrollmentType",
    "joinType",
    "viaWorkAccount",
    "complianceState",
    "enrolledDateTime",
    "lastSyncDateTime",
    "isNew",
  ];

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {errors.length > 0 && (
          <Grid size={12}>
            <Alert severity="warning">Some data could not be read: {errors.join("; ")}</Alert>
          </Grid>
        )}
        {allTenants && (
          <Grid size={12}>
            <Alert severity="info">
              All tenants are read from the CIPP reporting cache, so new enrollments appear after the next cache run.
              Select a single tenant to read it live.
            </Alert>
          </Grid>
        )}
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: <CippIcons.Devices />,
                data: report.data ? total("PersonalDevices") : "-",
                name: "Personally owned devices enrolled",
                color: total("PersonalDevices") > 0 ? "warning" : "success",
              },
              {
                icon: <CippIcons.LaptopWindows />,
                data: report.data ? `${total("Windows")} / ${total("WindowsViaWorkAccount")}` : "-",
                name: "Windows / enrolled by adding a work account",
                color: total("WindowsViaWorkAccount") > 0 ? "warning" : "info",
              },
              {
                icon: <CippIcons.Smartphone />,
                data: report.data ? `${total("iOS")} / ${total("Android")} / ${total("macOS")}` : "-",
                name: "iOS / Android / macOS",
                color: "info",
              },
              {
                icon: <CippIcons.NewReleases />,
                data: report.data ? `${total("NewDevices")} / ${total("NonCompliant")}` : "-",
                name: `New in ${report.data?.NewDays ?? 30} days / non-compliant`,
                color: total("NonCompliant") > 0 ? "error" : "info",
              },
            ]}
          />
        </Grid>
        {one && (
          <Grid size={12}>
            <CippInfoBar
              isFetching={report.isFetching}
              data={[
                {
                  icon: <CippIcons.Block />,
                  data: blockedText(one.PersonalBlockedWindows),
                  name: "Personal Windows enrollment (default platform restriction)",
                  color: blockedColor(one.PersonalBlockedWindows),
                },
                {
                  icon: <CippIcons.Policy />,
                  data:
                    one.MdmEnrollmentDuringRegistrationDisabled === true
                      ? "Disabled"
                      : one.MdmEnrollmentDuringRegistrationDisabled === false
                        ? "Enabled"
                        : "Unknown",
                  name: "MDM enrollment when adding a work or school account",
                  color: blockedColor(one.MdmEnrollmentDuringRegistrationDisabled),
                },
                {
                  icon: <CippIcons.Smartphone />,
                  data: `${blockedText(one.PersonalBlockediOS)} / ${blockedText(one.PersonalBlockedAndroidForWork)}`,
                  name: "Personal iOS / Android work profile enrollment",
                  color: "info",
                },
                {
                  icon: <CippIcons.Security />,
                  data: one.MdmUserScope || "Unknown",
                  name: "MDM user scope (automatic enrollment)",
                  color: "info",
                },
              ]}
            />
          </Grid>
        )}
        {allTenants && (
          <Grid size={12}>
            <CippDataTable
              title="Per-tenant summary and BYOD controls"
              data={tenants}
              isFetching={report.isFetching}
              queryKey="PersonalDevices-AllTenants-summary"
              simpleColumns={[
                "Tenant",
                "PersonalDevices",
                "Windows",
                "WindowsViaWorkAccount",
                "iOS",
                "Android",
                "macOS",
                "NewDevices",
                "NonCompliant",
                "PersonalBlockedWindows",
                "MdmEnrollmentDuringRegistrationDisabled",
                "PersonalBlockediOS",
                "PersonalBlockedAndroidForWork",
                "PersonalBlockedmacOS",
                "MdmUserScope",
                "CacheTimestamp",
              ]}
            />
          </Grid>
        )}
        <Grid size={12}>
          <CippDataTable
            title={`Personal devices - ${allTenants ? "All tenants" : tenant}`}
            data={devices}
            isFetching={report.isFetching}
            queryKey={`PersonalDevices-${tenant}-table`}
            simpleColumns={deviceColumns}
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
