// Out-of-office exposure (Aspendora fork, Vikunja CIPP-40).
// /api/ListOooExposure reads one tenant live and changes nothing. It lists mailboxes whose automatic reply goes
// to external senders and flags what the external message gives away (colleague addresses, phone numbers,
// travel, return dates, titles, finance cues). Why: an external OOO reply hands attackers the timing and the
// impersonation target for BEC payment fraud. The scripted alert "OooExposure" raises the High rows.
import { useState } from "react";
import { Alert, Button, Container, Grid, Stack } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { useSettings } from "../../../../hooks/use-settings";
import { ApiGetCall } from "../../../../api/ApiCall";

const Page = () => {
  const tenant = useSettings().currentTenant;
  const allTenants = !tenant || tenant === "AllTenants";
  const [includeUpcoming, setIncludeUpcoming] = useState(false);

  const report = ApiGetCall({
    url: "/api/ListOooExposure",
    data: { tenantFilter: tenant, includeUpcoming },
    queryKey: `OooExposure-${tenant}-${includeUpcoming}`,
    waiting: !allTenants,
  });

  if (allTenants) {
    return (
      <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
        <Alert severity="info">
          Select a single tenant. Auto-reply settings are read live, one tenant at a time.
        </Alert>
      </Container>
    );
  }

  const summary = report.data?.Summary;
  const rows = Array.isArray(report.data?.Rows) ? report.data.Rows : [];
  const errors = Array.isArray(report.data?.Errors) ? report.data.Errors : [];
  const noExchange = report.data?.Status === "NoExchange";

  const actions = [];

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {noExchange && (
          <Grid size={12}>
            <Alert severity="info">{report.data?.Message}</Alert>
          </Grid>
        )}
        {errors.length > 0 && (
          <Grid size={12}>
            <Alert severity="warning">Some data could not be read: {errors.join("; ")}</Alert>
          </Grid>
        )}
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: <CippIcons.Warning />,
                data: summary?.High ?? "-",
                name: "High: every external sender is told a colleague's address, a phone number or who handles payments",
                color: summary?.High ? "error" : "success",
              },
              {
                icon: <CippIcons.WarningAmber />,
                data: summary?.Medium ?? "-",
                name: "Medium: every external sender gets the reply (no contact or payment cues)",
                color: summary?.Medium ? "warning" : "success",
              },
              {
                icon: <CippIcons.Info />,
                data: summary?.Low ?? "-",
                name: "Low: external reply limited to known senders (contacts)",
                color: "info",
              },
              {
                icon: <CippIcons.Email />,
                data: report.data?.MailboxesChecked ?? "-",
                name: `Mailboxes checked${report.data?.GeneratedCentral ? ` (${report.data.GeneratedCentral})` : ""}`,
                color: "info",
              },
            ]}
          />
        </Grid>
        <Grid size={12}>
          <CippDataTable
            title={`Out-of-office exposure - ${tenant}`}
            data={rows}
            isFetching={report.isFetching}
            queryKey={`OooExposure-${tenant}-${includeUpcoming}-table`}
            actions={actions}
            offCanvas={{
              extendedInfoFields: [
                "DisplayName",
                "Mailbox",
                "Severity",
                "ExternalAudience",
                "AutoReplyState",
                "StartCentral",
                "EndCentral",
                "Reasons",
                "Recommendation",
                "ExternalMessageText",
              ],
              actions,
            }}
            simpleColumns={[
              "Severity",
              "DisplayName",
              "Mailbox",
              "ExternalAudience",
              "AutoReplyState",
              "Window",
              "StartCentral",
              "EndCentral",
              "FlagsText",
              "Reasons",
              "Snippet",
              "RecipientType",
            ]}
            cardButton={
              <Stack direction="row" spacing={1}>
                <Button
                  startIcon={<CippIcons.Schedule />}
                  disabled={report.isFetching}
                  onClick={() => setIncludeUpcoming((value) => !value)}
                >
                  {includeUpcoming ? "Hide upcoming" : "Show upcoming (14 days)"}
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
