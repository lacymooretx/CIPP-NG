// Out-of-office exposure (Aspendora fork, Vikunja CIPP-40).
// /api/ListOooExposure reads one tenant live and changes nothing. It lists mailboxes whose automatic reply goes
// to external senders and flags what the external message gives away (colleague addresses, phone numbers,
// travel, return dates, titles, finance cues). Why: an external OOO reply hands attackers the timing and the
// impersonation target for BEC payment fraud. The scripted alert "OooExposure" raises the High rows.
// The only write is the row action below: the existing ExecSetOoO endpoint with ExternalAudience Known plus the
// reply's current state and schedule, and no messages, so Exchange keeps both messages as they are.
import { useState } from "react";
import { Alert, Button, Container, Grid, Stack } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippInfoBar } from "../../../../components/CippCards/CippInfoBar";
import { CippIcons } from "../../../../utils/icon-registry";
import { useSettings } from "../../../../hooks/use-settings";
import { usePermissions } from "../../../../hooks/use-permissions";
import { ApiGetCall } from "../../../../api/ApiCall";

const Page = () => {
  const tenant = useSettings().currentTenant;
  const allTenants = !tenant || tenant === "AllTenants";
  const [includeUpcoming, setIncludeUpcoming] = useState(false);
  const { checkPermissions } = usePermissions();
  const canWriteMailbox = checkPermissions(["Exchange.Mailbox.ReadWrite"]);
  const queryKey = `OooExposure-${tenant}-${includeUpcoming}`;

  const report = ApiGetCall({
    url: "/api/ListOooExposure",
    data: { tenantFilter: tenant, includeUpcoming },
    queryKey,
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

  const actions = [
    {
      label: "Limit external replies to known senders",
      type: "POST",
      icon: <CippIcons.LockPerson />,
      url: "/api/ExecSetOoO",
      // "!" sends the literal value; the other strings are row fields. StartTime/EndTime are Unix seconds, the
      // same form the Exchange settings editor sends, and only used for Scheduled replies. No messages are sent.
      data: {
        userId: "Mailbox",
        AutoReplyState: "AutoReplyState",
        ExternalAudience: "!Known",
        StartTime: "StartTimeUnix",
        EndTime: "EndTimeUnix",
      },
      confirmText:
        "Limit the external out-of-office reply for [Mailbox] to known senders (contacts only)? The internal and external messages and the schedule stay as they are. Review the external message for colleague addresses, phone numbers and payment instructions as well.",
      multiPost: false,
      relatedQueryKeys: [queryKey],
      condition: (row) =>
        canWriteMailbox &&
        row.ExternalAudience === "All" &&
        (row.AutoReplyState === "Enabled" ||
          (row.AutoReplyState === "Scheduled" && row.StartTimeUnix && row.EndTimeUnix)),
    },
  ];

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
            queryKey={`${queryKey}-table`}
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
