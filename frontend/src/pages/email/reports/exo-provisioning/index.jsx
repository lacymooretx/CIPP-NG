// Exchange provisioning check (Aspendora fork, Vikunja CIPP-36).
// /api/ListExoProvisioningHealth reads one tenant live and changes nothing; it only runs when "Run check" is
// pressed because it reads every recipient and licensed user. The one write is the confirmed "Repair Exchange
// roles" button, which calls the existing ExecExchangeRoleRepair endpoint (needs CIPP.AppSettings.ReadWrite).
import { useState } from 'react'
import { Alert, Button, Container, Grid, Stack } from '@mui/material'
import { Layout as DashboardLayout } from '../../../../layouts/index'
import { CippDataTable } from '../../../../components/CippTable/CippDataTable'
import { CippInfoBar } from '../../../../components/CippCards/CippInfoBar'
import { CippApiDialog } from '../../../../components/CippComponents/CippApiDialog'
import { CippIcons } from '../../../../utils/icon-registry'
import { useSettings } from '../../../../hooks/use-settings'
import { usePermissions } from '../../../../hooks/use-permissions'
import { useDialog } from '../../../../hooks/use-dialog'
import { ApiGetCall } from '../../../../api/ApiCall'

const overallColor = {
  Pass: 'success',
  Warn: 'warning',
  Fail: 'error',
  Info: 'info',
}

const Page = () => {
  const tenant = useSettings().currentTenant
  const allTenants = !tenant || tenant === 'AllTenants'
  const { checkPermissions } = usePermissions()
  const canRepair = checkPermissions(['CIPP.AppSettings.ReadWrite'])
  const repairDialog = useDialog()
  const [started, setStarted] = useState(false)

  const report = ApiGetCall({
    url: '/api/ListExoProvisioningHealth',
    data: { tenantFilter: tenant },
    queryKey: `ExoProvisioningHealth-${tenant}`,
    waiting: started && !allTenants,
    retry: 1,
  })

  if (allTenants) {
    return (
      <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
        <Alert severity="info">
          Select a single tenant. The Exchange provisioning check is read live,
          one tenant at a time.
        </Alert>
      </Container>
    )
  }

  const summary = report.data?.Summary
  const checks = Array.isArray(report.data?.Checks) ? report.data.Checks : []
  const usersWithoutMailbox = Array.isArray(report.data?.UsersWithoutMailbox)
    ? report.data.UsersWithoutMailbox
    : []
  const missingDomains = Array.isArray(report.data?.MissingDomains)
    ? report.data.MissingDomains
    : []
  const missingRoles = Array.isArray(report.data?.MissingOrgManagementRoles)
    ? report.data.MissingOrgManagementRoles
    : []

  const runButton = (
    <Stack direction="row" spacing={1}>
      <Button
        startIcon={<CippIcons.PlayArrow />}
        disabled={report.isFetching}
        onClick={() => (started ? report.refetch() : setStarted(true))}
      >
        {report.isFetching
          ? 'Checking...'
          : started
            ? 'Run again'
            : 'Run check'}
      </Button>
      {canRepair && (
        <Button
          startIcon={<CippIcons.Plumbing />}
          color={summary?.RepairSuggested ? 'warning' : 'primary'}
          onClick={() => repairDialog.handleOpen()}
        >
          Repair Exchange roles
        </Button>
      )}
    </Stack>
  )

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {!started && (
          <Grid size={12}>
            <Alert severity="info">
              Run the check after onboarding a tenant or adding a SKU. It
              confirms Exchange Online answers, its role groups and roles exist,
              verified email domains are accepted, and licensed users have
              mailboxes. It changes nothing.
            </Alert>
          </Grid>
        )}
        {summary?.RepairSuggested && (
          <Grid size={12}>
            <Alert severity="warning">
              Organization Management is missing {missingRoles.length} role(s):{' '}
              {missingRoles.join(', ')}.{' '}
              {canRepair
                ? 'Use Repair Exchange roles, wait about 15 minutes, then run the check again.'
                : 'Ask a CIPP admin (CIPP.AppSettings.ReadWrite) to run the Exchange role repair.'}
            </Alert>
          </Grid>
        )}
        {summary?.NoExchangeLicence && (
          <Grid size={12}>
            <Alert severity="info">
              This tenant has no Exchange Online mailbox licence.
            </Alert>
          </Grid>
        )}
        {started && (
          <Grid size={12}>
            <CippInfoBar
              isFetching={report.isFetching}
              data={[
                {
                  icon: <CippIcons.Email />,
                  data: summary?.Overall ?? '-',
                  name: 'Overall',
                  color: overallColor[summary?.Overall] ?? 'info',
                },
                {
                  icon: <CippIcons.Error />,
                  data: summary ? `${summary.Fail} / ${summary.Warn}` : '-',
                  name: 'Failed / warning checks',
                  color: summary?.Fail
                    ? 'error'
                    : summary?.Warn
                      ? 'warning'
                      : 'success',
                },
                {
                  icon: <CippIcons.Domain />,
                  data: summary ? missingDomains.length : '-',
                  name: 'Email domains not accepted in Exchange',
                  color: missingDomains.length ? 'warning' : 'success',
                },
                {
                  icon: <CippIcons.Person />,
                  data: summary ? usersWithoutMailbox.length : '-',
                  name: `Licensed users without a mailbox (${report.data?.GraceHours ?? 24}h+)`,
                  color: usersWithoutMailbox.length ? 'warning' : 'success',
                },
              ]}
            />
          </Grid>
        )}
        <Grid size={12}>
          <CippDataTable
            title={`Exchange provisioning - ${tenant}`}
            data={checks}
            isFetching={report.isFetching}
            queryKey={`ExoProvisioningHealth-${tenant}-table`}
            simpleColumns={['Status', 'Check', 'Detail', 'Fix']}
            cardButton={runButton}
          />
        </Grid>
        {usersWithoutMailbox.length > 0 && (
          <Grid size={12}>
            <CippDataTable
              title="Licensed users without a mailbox"
              data={usersWithoutMailbox}
              queryKey={`ExoProvisioningHealth-${tenant}-users`}
              simpleColumns={[
                'userPrincipalName',
                'displayName',
                'licensedSince',
              ]}
            />
          </Grid>
        )}
      </Grid>
      <CippApiDialog
        createDialog={repairDialog}
        title="Repair Exchange roles"
        fields={[]}
        api={{
          url: '/api/ExecExchangeRoleRepair',
          type: 'POST',
          data: { tenantId: 'tenantId' },
          confirmText:
            'Assign every missing Organization Management role in [tenantId]? This runs the same repair as the Tenant access check. Wait about 15 minutes, then run the check again.',
        }}
        row={{ tenantId: tenant }}
      />
    </Container>
  )
}

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>

export default Page
