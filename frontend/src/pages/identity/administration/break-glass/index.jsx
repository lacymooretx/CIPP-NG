// Break-glass (emergency access) account registry (Aspendora fork, Vikunja CIPP-3 Phase 2).
// Lists the accounts watched by the BreakGlassActivity alert, registers and unregisters them, and shows
// Suggest results (likely break-glass accounts found from CA exclusions and account names).
import { Alert, Button, Stack, Typography } from "@mui/material";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import { TabbedLayout } from "../../../../layouts/TabbedLayout";
import tabOptions from "./tabOptions.json";
import CippTablePage from "../../../../components/CippComponents/CippTablePage";
import { CippApiDialog } from "../../../../components/CippComponents/CippApiDialog";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippIcons } from "../../../../utils/icon-registry";
import { useDialog } from "../../../../hooks/use-dialog";
import { useSettings } from "../../../../hooks/use-settings";
import { ApiGetCall } from "../../../../api/ApiCall";
import { useState } from "react";

const listKey = "BreakGlassAccounts";

const actions = [
  {
    label: "Unregister",
    type: "POST",
    url: "/api/ExecBreakGlassAccounts",
    data: { Action: "!Remove", UserId: "UserId" },
    confirmText:
      "Stop watching [UserPrincipalName]? Its sign-ins and changes will no longer raise break-glass alerts. Nothing changes on the account itself.",
    color: "danger",
    icon: <CippIcons.Delete />,
    relatedQueryKeys: [`${listKey}*`],
  },
];

const simpleColumns = ["Tenant", "UserPrincipalName", "DisplayName", "Note", "AddedBy", "AddedUtc"];

const Page = () => {
  const tenant = useSettings().currentTenant;
  const singleTenant = Boolean(tenant) && tenant !== "AllTenants";
  const addDialog = useDialog();
  const [suggestOn, setSuggestOn] = useState(false);

  const suggest = ApiGetCall({
    url: "/api/ExecBreakGlassAccounts",
    data: { tenantFilter: tenant, Action: "Suggest" },
    queryKey: `BreakGlassSuggest-${tenant}`,
    waiting: suggestOn && singleTenant,
  });
  const suggestions = Array.isArray(suggest.data?.Results) ? suggest.data.Results : [];

  const suggestActions = [
    {
      label: "Register as break-glass",
      type: "POST",
      url: "/api/ExecBreakGlassAccounts",
      data: { Action: "!Add", UserId: "UserId" },
      fields: [{ name: "Note", label: "Note (optional)", type: "textField" }],
      confirmText:
        "Register [UserPrincipalName] as a break-glass account? Any sign-in or change to it will raise a High alert.",
      color: "info",
      icon: <CippIcons.PersonAdd />,
      relatedQueryKeys: [`${listKey}*`, "BreakGlassSuggest*"],
      condition: (row) => row?.Registered !== true,
    },
  ];

  return (
    <>
      <CippTablePage
        title="Break-glass accounts"
        apiUrl="/api/ExecBreakGlassAccounts"
        apiData={{ Action: "List" }}
        apiDataKey="Results"
        queryKey={`${listKey}-${tenant}`}
        simpleColumns={simpleColumns}
        actions={actions}
        offCanvas={{ actions, extendedInfoFields: [...simpleColumns, "TenantId", "UserId"] }}
        cardButton={
          <Stack direction="row" spacing={1}>
            <Button
              startIcon={<CippIcons.PersonAdd />}
              disabled={!singleTenant}
              onClick={addDialog.handleOpen}
            >
              Register account
            </Button>
            <Button
              startIcon={<CippIcons.Search />}
              disabled={!singleTenant || suggest.isFetching}
              onClick={() => (suggestOn ? suggest.refetch() : setSuggestOn(true))}
            >
              {suggest.isFetching ? "Looking..." : "Suggest accounts"}
            </Button>
          </Stack>
        }
      />
      <Stack spacing={1} sx={{ px: 3, pb: 3 }}>
        {!singleTenant && (
          <Alert severity="info">
            Pick a single tenant to register an account or to look for likely break-glass accounts.
          </Alert>
        )}
        <Typography variant="caption" color="text.secondary">
          Registered accounts are watched by the "Break-glass account activity" alert (every 30 minutes, on the
          tenants it is scheduled for) and checked weekly by the break-glass posture alert.
        </Typography>
        {suggestOn && singleTenant && (
          <CippDataTable
            title={`Suggested break-glass accounts - ${tenant}`}
            data={suggestions}
            isFetching={suggest.isFetching}
            queryKey={`BreakGlassSuggest-${tenant}-table`}
            simpleColumns={["UserPrincipalName", "DisplayName", "Reason", "Registered"]}
            actions={suggestActions}
            noDataButton={{ createText: "No likely break-glass accounts found" }}
          />
        )}
      </Stack>
      <CippApiDialog
        createDialog={addDialog}
        title="Register a break-glass account"
        fields={[
          {
            name: "UserPrincipalName",
            label: "User principal name (or object id)",
            type: "textField",
            required: true,
          },
          { name: "Note", label: "Note (optional, e.g. where the credentials are kept)", type: "textField" },
        ]}
        api={{
          type: "POST",
          url: "/api/ExecBreakGlassAccounts",
          data: { Action: "!Add" },
          confirmText:
            "Register this account in the current tenant? Any sign-in or change to it will raise a High alert.",
          relatedQueryKeys: [`${listKey}*`],
        }}
        relatedQueryKeys={[`${listKey}*`]}
      />
    </>
  );
};

Page.getLayout = (page) => (
  <DashboardLayout allTenantsSupport={true}>
    <TabbedLayout tabOptions={tabOptions}>{page}</TabbedLayout>
  </DashboardLayout>
);

export default Page;
