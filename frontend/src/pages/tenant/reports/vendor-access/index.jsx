// Vendor Access report (Aspendora fork).
// Every outside party with standing access to client tenants: foreign apps, other organisations' groups and accounts
// holding directory roles (other partners' GDAP/DAP), guests holding directory roles and cross-tenant service
// providers. /api/ListVendorAccess reads the saved snapshot (rebuilt weekly for the Monday email, or by Refresh).
// The only write on this page is the existing ExecApplication disable/enable for an app, after a confirmation.
import { useState } from 'react'
import {
  Alert,
  Button,
  Container,
  Grid,
  Stack,
  Typography,
} from '@mui/material'
import { Layout as DashboardLayout } from '../../../../layouts/index'
import { CippDataTable } from '../../../../components/CippTable/CippDataTable'
import { CippInfoBar } from '../../../../components/CippCards/CippInfoBar'
import { CippIcons } from '../../../../utils/icon-registry'
import { useSettings } from '../../../../hooks/use-settings'
import { usePermissions } from '../../../../hooks/use-permissions'
import { ApiGetCall, ApiPostCall } from '../../../../api/ApiCall'

const kindLabels = {
  App: 'App',
  ForeignRoleHolder: 'Outside admin (GDAP/DAP)',
  GuestRoleHolder: 'Guest admin',
  ServiceProvider: 'Service provider',
}

const filters = [
  {
    filterName: 'Critical risk',
    value: [{ id: 'Risk', value: 'Critical' }],
    type: 'column',
  },
  {
    filterName: 'High risk',
    value: [{ id: 'Risk', value: 'High' }],
    type: 'column',
  },
  {
    filterName: 'New this week',
    value: [{ id: 'IsNew', value: 'Yes' }],
    type: 'column',
  },
  {
    filterName: 'Stale',
    value: [{ id: 'Stale', value: 'Yes' }],
    type: 'column',
  },
  {
    filterName: 'Outside admins (other partners)',
    value: [{ id: 'Type', value: kindLabels.ForeignRoleHolder }],
    type: 'column',
  },
  {
    filterName: 'Guest admins',
    value: [{ id: 'Type', value: kindLabels.GuestRoleHolder }],
    type: 'column',
  },
  {
    filterName: 'Apps',
    value: [{ id: 'Type', value: kindLabels.App }],
    type: 'column',
  },
  {
    filterName: 'Removed this week',
    value: [{ id: 'Removed', value: 'Yes' }],
    type: 'column',
  },
]

const formatCentral = (value) => {
  if (!value) return 'never'
  try {
    return new Date(value).toLocaleString('en-US', {
      timeZone: 'America/Chicago',
      dateStyle: 'medium',
      timeStyle: 'short',
      timeZoneName: 'short',
    })
  } catch {
    return String(value)
  }
}

const Page = () => {
  const tenant = useSettings().currentTenant || 'AllTenants'
  const allTenants = tenant === 'AllTenants'
  const { checkPermissions } = usePermissions()
  const canWriteApplication = checkPermissions(['Tenant.Application.ReadWrite'])
  const [refresh, setRefresh] = useState(0)

  const report = ApiGetCall({
    url: '/api/ListVendorAccess',
    data: refresh
      ? { tenantFilter: tenant, Refresh: true }
      : { tenantFilter: tenant },
    queryKey: `VendorAccess-${tenant}-${refresh}`,
  })
  const settings = ApiGetCall({
    url: '/api/ExecVendorAccessReport',
    data: { Action: 'GetSettings' },
    queryKey: 'VendorAccessSettings',
  })
  const sendNow = ApiPostCall({ relatedQueryKeys: ['VendorAccessSettings'] })

  const summary = report.data?.Summary
  const tenants = Array.isArray(report.data?.Tenants) ? report.data.Tenants : []
  const rawItems = Array.isArray(report.data?.Items) ? report.data.Items : []
  const items = rawItems.map((item) => ({
    ...item,
    Type: kindLabels[item.Kind] ?? item.Kind,
    IsNew: item.IsNew ? 'Yes' : 'No',
    Removed: item.Removed ? 'Yes' : 'No',
    Stale:
      item.Stale === true ? 'Yes' : item.Stale === false ? 'No' : 'Unknown',
    Who: item.Name,
  }))
  const problems = tenants.filter(
    (t) => t.LastError || (Array.isArray(t.Errors) && t.Errors.length > 0)
  )
  const noP1 = tenants.filter((t) => t.SignInActivityAvailable === false)

  const actions = [
    {
      icon: <CippIcons.EyeIcon />,
      label: 'View app in CIPP',
      link: '/tenant/administration/applications/enterprise-app?spId=[ObjectId]&tenantFilter=[Tenant]',
      color: 'info',
      multiPost: false,
      external: false,
      condition: (row) => row?.Kind === 'App' && row?.ObjectId,
    },
    {
      icon: <CippIcons.Block />,
      label: 'Disable app (vendor kill switch)',
      type: 'POST',
      color: 'warning',
      multiPost: false,
      url: '/api/ExecApplication',
      data: {
        Id: 'ObjectId',
        Type: 'servicePrincipals',
        Action: 'Update',
        Payload: { accountEnabled: false },
      },
      confirmText:
        "Disable '[Name]' in [Tenant]? It stops signing in and getting tokens in this tenant at once. Its permissions stay in place and it can be enabled again.",
      condition: (row) =>
        canWriteApplication &&
        row?.Kind === 'App' &&
        row?.ObjectId &&
        row?.Enabled !== false,
    },
    {
      icon: <CippIcons.CheckCircle />,
      label: 'Enable app',
      type: 'POST',
      color: 'info',
      multiPost: false,
      url: '/api/ExecApplication',
      data: {
        Id: 'ObjectId',
        Type: 'servicePrincipals',
        Action: 'Update',
        Payload: { accountEnabled: true },
      },
      confirmText: "Enable '[Name]' in [Tenant] again?",
      condition: (row) =>
        canWriteApplication &&
        row?.Kind === 'App' &&
        row?.ObjectId &&
        row?.Enabled === false,
    },
  ]

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        <Grid size={12}>
          <Alert severity="info">
            Everyone outside the client who holds standing access: apps owned by
            other organisations, groups and accounts from other organisations
            holding directory roles (this is how another partner&apos;s GDAP or
            DAP access shows up), guests holding directory roles, and
            cross-tenant service providers. Aspendora&apos;s own CIPP partner
            tenant is listed but not counted. Stale means no sign-in for 45+
            days; Unknown means the tenant has no Entra ID P1, so sign-ins
            cannot be read.
          </Alert>
        </Grid>
        {problems.length > 0 && (
          <Grid size={12}>
            <Alert severity="warning">
              Not fully checked:{' '}
              {problems
                .map(
                  (t) =>
                    `${t.TenantName}: ${[t.LastError, ...(t.Errors ?? [])].filter(Boolean).join('; ')}`
                )
                .join(' | ')}
            </Alert>
          </Grid>
        )}
        {noP1.length > 0 && (
          <Grid size={12}>
            <Alert severity="info">
              No app sign-in data (no Entra ID P1):{' '}
              {noP1.map((t) => t.TenantName).join(', ')}.
            </Alert>
          </Grid>
        )}
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: <CippIcons.Public />,
                data: summary
                  ? `${summary.ThirdPartyItems} / ${summary.Organisations}`
                  : '-',
                name: 'Outside parties / organisations',
                color: 'info',
              },
              {
                icon: <CippIcons.Warning />,
                data: summary?.HighRisk ?? '-',
                name: `High or critical risk${summary?.Critical ? ` (${summary.Critical} critical)` : ''}`,
                color: summary?.HighRisk ? 'error' : 'success',
              },
              {
                icon: <CippIcons.PersonAdd />,
                data: summary?.New ?? '-',
                name: `New this week${summary?.Removed ? `, ${summary.Removed} removed` : ''}`,
                color: summary?.New ? 'warning' : 'success',
              },
              {
                icon: <CippIcons.Schedule />,
                data: summary
                  ? `${summary.Stale} / ${summary.SignInUnknown}`
                  : '-',
                name: 'Stale 45+ days / sign-in unknown',
                color: summary?.Stale ? 'warning' : 'success',
              },
            ]}
          />
        </Grid>
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: <CippIcons.Apps />,
                data: summary
                  ? `${summary.Apps} (${summary.AppsWithPermissions} with permissions)`
                  : '-',
                name: 'Apps from other organisations',
                color: 'info',
              },
              {
                icon: <CippIcons.AdminPanelSettings />,
                data: summary?.ForeignRoleHolders ?? '-',
                name: 'Outside admin groups/accounts (other partners)',
                color: summary?.ForeignRoleHolders ? 'warning' : 'info',
              },
              {
                icon: <CippIcons.Group />,
                data: summary?.GuestRoleHolders ?? '-',
                name: 'Guests holding roles',
                color: summary?.GuestRoleHolders ? 'warning' : 'info',
              },
              {
                icon: <CippIcons.Business />,
                data: summary?.ServiceProviders ?? '-',
                name: 'Cross-tenant service providers',
                color: 'info',
              },
            ]}
          />
        </Grid>
        <Grid size={12}>
          <Stack
            direction="row"
            spacing={2}
            alignItems="center"
            flexWrap="wrap"
          >
            <Typography variant="body2" color="text.secondary">
              Data from {formatCentral(report.data?.GeneratedAt)}. Weekly email:{' '}
              {settings.data
                ? `${settings.data.Enabled ? 'on' : 'off'}, ${settings.data.Schedule} to ${settings.data.Recipient}`
                : '...'}
              {settings.data?.Sends?.[0]
                ? `. Last: ${settings.data.Sends[0].Day} ${settings.data.Sends[0].Status}`
                : ''}
            </Typography>
          </Stack>
        </Grid>
        <Grid size={12}>
          <CippDataTable
            title={`Vendor Access - ${allTenants ? 'All tenants' : tenant}`}
            data={items}
            isFetching={report.isFetching}
            queryKey={`VendorAccess-${tenant}-table`}
            actions={actions}
            filters={filters}
            simpleColumns={[
              ...(allTenants ? ['TenantName'] : []),
              'Type',
              'Who',
              'Organisation',
              'OrganisationType',
              'Vendor',
              'Risk',
              'Access',
              'SignInActivity',
              'LastSignInDateTime',
              'Stale',
              'NewCredentials',
              'IsNew',
              'Removed',
              'FirstSeen',
              'Enabled',
            ]}
            offCanvas={{
              size: 'lg',
              actions,
              children: (row) => (
                <Stack spacing={1.5} sx={{ p: 1 }}>
                  <Typography variant="h6">{row.Name}</Typography>
                  <Typography variant="body2">
                    {row.Type} in {row.TenantName || row.Tenant} &middot;{' '}
                    {row.Organisation} ({row.OrganisationType})
                    {row.Vendor ? ` · vendor ${row.Vendor}` : ''}
                  </Typography>
                  <Typography variant="subtitle2">Risk: {row.Risk}</Typography>
                  {(row.RiskReasons ?? []).map((reason, i) => (
                    <Typography key={i} variant="body2" color="text.secondary">
                      &bull; {reason}
                    </Typography>
                  ))}
                  <Typography variant="subtitle2">Access</Typography>
                  <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                    {String(row.Access ?? '')
                      .split('; ')
                      .join('\n')}
                  </Typography>
                  <Typography variant="subtitle2">Sign-in</Typography>
                  <Typography variant="body2">
                    {row.SignInActivity}
                    {row.LastSignInDateTime
                      ? ` · last ${formatCentral(row.LastSignInDateTime)}`
                      : ''}
                  </Typography>
                  {row.OrganisationId && (
                    <Typography variant="caption" color="text.secondary">
                      Organisation tenant ID: {row.OrganisationId}
                    </Typography>
                  )}
                  {row.Kind === 'ForeignRoleHolder' && (
                    <Alert severity="info">
                      To remove another partner&apos;s access, the
                      customer&apos;s Global Administrator ends the relationship
                      in the Microsoft 365 admin center (Settings &gt; Partner
                      relationships). See the Vendor Access article in Hudu.
                    </Alert>
                  )}
                </Stack>
              ),
            }}
            cardButton={
              <Stack direction="row" spacing={1}>
                <Button
                  startIcon={<CippIcons.Refresh />}
                  disabled={report.isFetching}
                  onClick={() => setRefresh(Date.now())}
                >
                  {report.isFetching ? 'Reading...' : 'Rebuild now'}
                </Button>
                {canWriteApplication && (
                  <Button
                    startIcon={<CippIcons.Email />}
                    disabled={sendNow.isPending}
                    onClick={() =>
                      sendNow.mutate({
                        url: '/api/ExecVendorAccessReport',
                        data: { Action: 'Send', SkipRefresh: true },
                      })
                    }
                  >
                    {sendNow.isPending ? 'Sending...' : 'Email it now'}
                  </Button>
                )}
              </Stack>
            }
          />
          {sendNow.isSuccess && (
            <Alert severity="success" sx={{ mt: 1 }}>
              {sendNow.data?.data?.Results ?? 'Sent'}
            </Alert>
          )}
          {sendNow.isError && (
            <Alert severity="error" sx={{ mt: 1 }}>
              {sendNow.error?.response?.data?.Results ??
                'The email could not be sent'}
            </Alert>
          )}
        </Grid>
      </Grid>
    </Container>
  )
}

Page.getLayout = (page) => (
  <DashboardLayout allTenantsSupport={true}>{page}</DashboardLayout>
)

export default Page
