// What Changed (Aspendora fork, Vikunja CIPP-58, stage 1: no AI and no email).
// /api/ListTenantChanges reads data CIPP already holds and changes nothing. A day with no changes gets one line, and a
// source that could not be read says so instead of counting as no changes.
import { useState } from 'react'
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Button,
  Container,
  Grid,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { Layout as DashboardLayout } from '../../../../layouts/index'
import { CippDataTable } from '../../../../components/CippTable/CippDataTable'
import { CippInfoBar } from '../../../../components/CippCards/CippInfoBar'
import { CippIcons } from '../../../../utils/icon-registry'
import { useSettings } from '../../../../hooks/use-settings'
import { ApiGetCall } from '../../../../api/ApiCall'
import { getCippError } from '../../../../utils/get-cipp-error'
import {
  countOrUnknown,
  failedSources,
  limitedSources,
  verdictLine,
  windowLabel,
} from '../../../../utils/tenant-changes'

const simpleColumns = ['Source', 'Change', 'Risk', 'Title', 'Detail', 'When']

const sourceFilter = (name) => ({
  filterName: name,
  value: [{ id: 'Source', value: name }],
  type: 'column',
})

const filters = [
  'Alerts',
  'Test results',
  'Secure Score',
  'Message Center',
].map(sourceFilter)

const actions = [
  {
    label: 'Open in Message Center',
    link: '[Link]',
    external: true,
    color: 'info',
    icon: <CippIcons.Launch />,
    condition: (row) => Boolean(row.Link),
  },
]

const Page = () => {
  const tenant = useSettings().currentTenant
  const allTenants = tenant === 'AllTenants'
  const [days, setDays] = useState(1)
  const queryKey = `TenantChanges-${tenant}-${days}`
  const report = ApiGetCall({
    url: '/api/ListTenantChanges',
    data: { tenantFilter: tenant, days },
    queryKey,
    waiting: Boolean(tenant) && !allTenants,
  })

  // Every source failing is a 500 that still carries the record, so read it from the error as well.
  const record = report.data ?? report.error?.response?.data ?? {}
  const sources = Array.isArray(record.Sources) ? record.Sources : []
  const changes = Array.isArray(record.Changes) ? record.Changes : []
  const olderChanges = Array.isArray(record.OlderTestChanges)
    ? record.OlderTestChanges
    : []
  const summary = record.Summary ?? {}
  const failed = failedSources(sources)
  const limited = limitedSources(sources).filter(
    (source) => source.Name !== 'Health'
  )
  const line = verdictLine(record)
  const requestFailed = report.isError && sources.length === 0

  const controls = (
    <Stack direction="row" spacing={2} alignItems="center">
      <TextField
        select
        size="small"
        label="Window"
        value={days}
        onChange={(event) => setDays(Number(event.target.value))}
      >
        <MenuItem value={1}>Last 24 hours</MenuItem>
        <MenuItem value={3}>Last 3 days</MenuItem>
        <MenuItem value={7}>Last 7 days</MenuItem>
        <MenuItem value={30}>Last 30 days</MenuItem>
      </TextField>
      <Button
        startIcon={<CippIcons.Refresh />}
        disabled={report.isFetching}
        onClick={() => report.refetch()}
      >
        {report.isFetching ? 'Reading...' : 'Refresh'}
      </Button>
    </Stack>
  )

  if (allTenants) {
    return (
      <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
        <Alert severity="info">
          Select a single tenant. The change record is per tenant.
        </Alert>
      </Container>
    )
  }

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        <Grid size={12}>
          <Stack
            direction="row"
            justifyContent="space-between"
            alignItems="center"
            spacing={2}
          >
            <Typography variant="body2" color="text.secondary">
              Times are US Central with UTC alongside.
              {record.GeneratedAt ? ` Read ${record.GeneratedAt}.` : ''}
            </Typography>
            {controls}
          </Stack>
        </Grid>
        {requestFailed && (
          <Grid size={12}>
            <Alert severity="error">
              Could not read the change record: {getCippError(report.error)}
            </Alert>
          </Grid>
        )}
        {failed.map((source) => (
          <Grid size={12} key={source.Name}>
            <Alert severity="warning">
              {source.Label}: could not read. {source.Detail}
            </Alert>
          </Grid>
        ))}
        {line && (
          <Grid size={12}>
            <Alert severity={line.severity}>{line.text}</Alert>
          </Grid>
        )}
        {limited.map((source) => (
          <Grid size={12} key={source.Name}>
            <Alert severity="info">
              {source.Label}: {source.StatusText.toLowerCase()}. {source.Detail}
            </Alert>
          </Grid>
        ))}
        {changes.length > 0 && (
          <>
            <Grid size={12}>
              <CippInfoBar
                isFetching={report.isFetching}
                data={[
                  {
                    icon: <CippIcons.Warning />,
                    data: countOrUnknown(summary.NewAlerts, sources, 'Alerts'),
                    name: `New alerts (${countOrUnknown(summary.ReopenedAlerts, sources, 'Alerts')} reopened)`,
                    color: summary.NewAlerts ? 'warning' : 'secondary',
                  },
                  {
                    icon: <CippIcons.CheckCircle />,
                    data: countOrUnknown(
                      summary.ResolvedAlerts,
                      sources,
                      'Alerts'
                    ),
                    name: 'Resolved alerts',
                    color: 'success',
                  },
                  {
                    icon: <CippIcons.Security />,
                    data: countOrUnknown(summary.NewIssues, sources, 'Tests'),
                    name: `New test issues (${countOrUnknown(summary.FixedTests, sources, 'Tests')} fixed)`,
                    color: summary.NewIssues ? 'warning' : 'secondary',
                  },
                  {
                    icon: <CippIcons.Schedule />,
                    data: countOrUnknown(
                      summary.MessageCenter,
                      sources,
                      'MessageCenter'
                    ),
                    name: 'Message Center items',
                    color: 'info',
                  },
                ]}
              />
            </Grid>
            <Grid size={12}>
              <CippDataTable
                title={`What changed in ${windowLabel(record.Days ?? days)}`}
                data={changes}
                isFetching={report.isFetching}
                queryKey={`${queryKey}-table`}
                simpleColumns={simpleColumns}
                filters={filters}
                actions={actions}
                offCanvas={{ actions, extendedInfoFields: simpleColumns }}
              />
            </Grid>
          </>
        )}
        {olderChanges.length > 0 && (
          <Grid size={12}>
            <Accordion>
              <AccordionSummary expandIcon={<CippIcons.ExpandMore />}>
                <Typography>
                  {olderChanges.length} test result changes since the snapshot
                  of {record.TestBaselineDate}, which cannot be dated any closer
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <CippDataTable
                  title="Test result changes since the snapshot"
                  data={olderChanges}
                  isFetching={report.isFetching}
                  queryKey={`${queryKey}-older`}
                  simpleColumns={['Change', 'Risk', 'Title', 'Detail', 'When']}
                />
              </AccordionDetails>
            </Accordion>
          </Grid>
        )}
        {sources.length > 0 && (
          <Grid size={12}>
            <Accordion>
              <AccordionSummary expandIcon={<CippIcons.ExpandMore />}>
                <Typography>Sources and data age</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Stack spacing={1}>
                  {sources.map((source) => (
                    <Typography variant="body2" key={source.Name}>
                      <strong>{source.Label}</strong> ({source.StatusText}):{' '}
                      {source.Detail}
                    </Typography>
                  ))}
                </Stack>
              </AccordionDetails>
            </Accordion>
          </Grid>
        )}
      </Grid>
    </Container>
  )
}

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>

export default Page
