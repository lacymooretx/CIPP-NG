// Message Center digest (Aspendora fork, Vikunja CIPP-37).
// /api/ListMessageCenterDigest reads the cached Message Center posts and changes nothing. Each post appears once
// with the tenants it reached, classified by the rules in Get-CIPPMessageCenterClassification. The weekly
// MessageCenterDigest alert raises the same action-required, retirement and security rows.
import { useState } from 'react'
import {
  Alert,
  Button,
  Container,
  FormControlLabel,
  Grid,
  Stack,
  Switch,
} from '@mui/material'
import { Layout as DashboardLayout } from '../../../../layouts/index'
import CippTablePage from '../../../../components/CippComponents/CippTablePage'
import { CippInfoBar } from '../../../../components/CippCards/CippInfoBar'
import { CippIcons } from '../../../../utils/icon-registry'
import { useSettings } from '../../../../hooks/use-settings'
import { ApiGetCall } from '../../../../api/ApiCall'

const simpleColumns = [
  'CategoryLabel',
  'DeadlineStatus',
  'Deadline',
  'DaysLeft',
  'MessageId',
  'Title',
  'TenantCount',
  'TenantsText',
  'WindowReason',
  'Services',
  'LastUpdated',
]

const categoryFilter = (name, label) => ({
  filterName: label,
  value: [{ id: 'CategoryLabel', value: name }],
  type: 'column',
})

// CategoryLabel values come from the rule table in Get-CIPPMessageCenterClassification.ps1.
const filters = [
  categoryFilter('Action required / deadline', 'Action required'),
  categoryFilter('Retirement', 'Retirements'),
  categoryFilter('Security / compliance', 'Security / compliance'),
  categoryFilter('New feature off by default / opt-in', 'Opt-in features'),
  categoryFilter('On by default (admin opt-out)', 'On by default'),
  categoryFilter('Informational', 'Informational'),
  {
    filterName: 'Due soon',
    value: [{ id: 'DeadlineStatus', value: 'Due soon' }],
    type: 'column',
  },
  {
    filterName: 'Overdue',
    value: [{ id: 'DeadlineStatus', value: 'Overdue' }],
    type: 'column',
  },
]

const actions = [
  {
    label: 'Open in Message Center',
    link: 'https://admin.microsoft.com/#/MessageCenter/:/messages/[MessageId]',
    external: true,
    color: 'info',
    icon: <CippIcons.Launch />,
  },
]

const Page = () => {
  const tenant = useSettings().currentTenant
  const [includeInformational, setIncludeInformational] = useState(false)
  const queryKey = `MessageCenterDigest-${tenant}-${includeInformational}`
  const report = ApiGetCall({
    url: '/api/ListMessageCenterDigest',
    data: { tenantFilter: tenant, includeInformational },
    queryKey,
    waiting: Boolean(tenant),
  })

  const data = report.data ?? {}
  const items = Array.isArray(data.Items) ? data.Items : []
  const summary = data.Summary ?? {}
  const byCategory = summary.ByCategory ?? {}
  const notCached = Array.isArray(summary.NotCached) ? summary.NotCached : []
  const failed = typeof data.Results === 'string' ? data.Results : null

  return (
    <Container maxWidth={false} sx={{ flexGrow: 1, py: 2 }}>
      <Grid container spacing={2}>
        {failed && (
          <Grid size={12}>
            <Alert severity="error">{failed}</Alert>
          </Grid>
        )}
        {notCached.length > 0 && (
          <Grid size={12}>
            <Alert severity="warning">
              No cached Message Center posts for: {notCached.join(', ')}. Run
              the CIPP DB cache for those tenants to include them.
            </Alert>
          </Grid>
        )}
        <Grid size={12}>
          <CippInfoBar
            isFetching={report.isFetching}
            data={[
              {
                icon: <CippIcons.Schedule />,
                data: summary.DueSoon ?? '-',
                name: `Deadlines within ${summary.DeadlineDays ?? 30} days (${summary.Overdue ?? 0} overdue)`,
                color: summary.DueSoon ? 'error' : 'success',
              },
              {
                icon: <CippIcons.Warning />,
                data: byCategory.ActionRequired ?? '-',
                name: 'Action required',
                color: byCategory.ActionRequired ? 'warning' : 'success',
              },
              {
                icon: <CippIcons.Delete />,
                data: byCategory.Retirement ?? '-',
                name: 'Retirements',
                color: 'warning',
              },
              {
                icon: <CippIcons.Security />,
                data: byCategory.Security ?? '-',
                name: 'Security / compliance',
                color: 'info',
              },
              {
                icon: <CippIcons.Info />,
                data:
                  summary.Total != null
                    ? `${summary.Total} of ${summary.PostsRead ?? 0} posts, ${summary.TenantsCovered ?? 0} tenants`
                    : '-',
                name: `Last ${summary.Days ?? 7} days, cache from ${summary.OldestCache || 'n/a'}`,
                color: 'secondary',
              },
            ]}
          />
        </Grid>
        <Grid size={12}>
          <CippTablePage
            title="Message Center Digest"
            data={items}
            isFetching={report.isFetching}
            queryKey={`${queryKey}-table`}
            actions={actions}
            offCanvas={{
              actions,
              extendedInfoFields: [
                ...simpleColumns,
                'Reasons',
                'Flags',
                'Summary',
                'Tags',
                'MicrosoftCategory',
                'Severity',
                'IsMajorChange',
                'Published',
                'Link',
              ],
            }}
            simpleColumns={simpleColumns}
            filters={filters}
            cardButton={
              <Stack direction="row" spacing={2} alignItems="center">
                <FormControlLabel
                  control={
                    <Switch
                      checked={includeInformational}
                      onChange={(event) =>
                        setIncludeInformational(event.target.checked)
                      }
                    />
                  }
                  label="Include informational"
                />
                <Button
                  startIcon={<CippIcons.Refresh />}
                  disabled={report.isFetching}
                  onClick={() => report.refetch()}
                >
                  {report.isFetching ? 'Reading...' : 'Refresh'}
                </Button>
              </Stack>
            }
          />
        </Grid>
      </Grid>
    </Container>
  )
}

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>

export default Page
