import { Layout as DashboardLayout } from '../../../../layouts/index.js'
import { useSettings } from '../../../../hooks/use-settings'
import { ApiGetCall } from '../../../../api/ApiCall.jsx'
import { Card, CardContent, CardHeader, Alert, Typography, Divider, Chip, Skeleton } from '@mui/material'
import { Box, Container, Grid, Stack } from '@mui/system'
import { useTheme } from '@mui/material/styles'
import { CippHead } from '../../../../components/CippComponents/CippHead.jsx'
import { Chart } from '../../../../components/chart'

// Binary units, matching how Microsoft reports and how the backend report renders. Using
// decimal GB here would put a different number on the page than in the emailed report for
// the same tenant, which is the kind of discrepancy that costs an hour to chase down.
const formatBytes = (bytes) => {
  const b = Number(bytes) || 0
  if (Math.abs(b) >= 1024 ** 4) return `${(b / 1024 ** 4).toFixed(2)} TB`
  if (Math.abs(b) >= 1024 ** 3) return `${(b / 1024 ** 3).toFixed(2)} GB`
  if (Math.abs(b) >= 1024 ** 2) return `${(b / 1024 ** 2).toFixed(1)} MB`
  return `${(b / 1024).toFixed(0)} KB`
}

const formatRate = (bytesPerDay) => {
  const b = Number(bytesPerDay) || 0
  return `${b < 0 ? '-' : '+'}${formatBytes(Math.abs(b))}/day`
}

const TREND_COLOUR = {
  Accelerating: 'warning',
  Growing: 'info',
  Flat: 'default',
  Shrinking: 'success',
  Unknown: 'default',
}

const Tile = ({ label, value, caption }) => (
  <Card sx={{ height: '100%' }}>
    <CardContent>
      <Typography color="text.secondary" variant="overline">
        {label}
      </Typography>
      <Typography variant="h5" sx={{ mt: 0.5 }}>
        {value}
      </Typography>
      {caption && (
        <Typography color="text.secondary" variant="caption">
          {caption}
        </Typography>
      )}
    </CardContent>
  </Card>
)

const Page = () => {
  const { currentTenant } = useSettings()
  const theme = useTheme()

  const trendApi = ApiGetCall({
    url: '/api/ListStorageTrend',
    data: { TenantFilter: currentTenant },
    queryKey: `ListStorageTrend-${currentTenant}`,
    waiting: !!currentTenant && currentTenant !== 'AllTenants',
  })

  const data = trendApi.data ?? {}
  const series = Array.isArray(data.Series) ? data.Series : []
  const growth = data.Growth ?? {}
  const latest = data.Latest ?? null

  const chartOptions = {
    chart: { type: 'area', stacked: true, toolbar: { show: false }, zoom: { enabled: false } },
    theme: { mode: theme.palette.mode },
    dataLabels: { enabled: false },
    stroke: { curve: 'smooth', width: 2 },
    fill: { type: 'gradient', gradient: { opacityFrom: 0.4, opacityTo: 0.05 } },
    xaxis: {
      categories: series.map((p) => p.Date),
      type: 'category',
      // 180 daily labels is an unreadable smear; let ApexCharts thin them out.
      tickAmount: 8,
      labels: { rotate: 0 },
    },
    yaxis: {
      labels: { formatter: (v) => formatBytes(v) },
    },
    tooltip: { y: { formatter: (v) => formatBytes(v) } },
    legend: { position: 'top' },
    colors: ['#B71A28', '#2e7d32', '#0288d1'],
  }

  const chartSeries = [
    { name: 'Exchange', data: series.map((p) => p.MailboxBytes) },
    { name: 'OneDrive', data: series.map((p) => p.OneDriveBytes) },
    { name: 'SharePoint', data: series.map((p) => p.SharePointBytes) },
  ]

  return (
    <>
      <CippHead title="M365 Storage & Usage" />
      <Box sx={{ flexGrow: 1, py: 4 }}>
        <Container maxWidth={false}>
          <Stack spacing={3}>
            <Typography variant="h4">M365 Storage &amp; Usage</Typography>

            {(!currentTenant || currentTenant === 'AllTenants') && (
              <Alert severity="info">
                Select a single tenant. Storage history is stored per tenant, and an
                all-tenants total would add together clients with unrelated quotas.
              </Alert>
            )}

            {trendApi.isLoading && <Skeleton variant="rounded" height={320} />}

            {trendApi.isSuccess && data.Collected === false && (
              <Alert severity={data.ManagementStatus === 'Managed' ? 'info' : 'warning'}>
                {data.Message}
              </Alert>
            )}

            {trendApi.isSuccess && data.Collected && (
              <>
                <Grid container spacing={3}>
                  <Grid size={{ xs: 12, md: 3 }}>
                    <Tile
                      label="Total consumption"
                      value={formatBytes(latest?.TotalBytes)}
                      caption={`as at ${latest?.Date ?? 'unknown'}`}
                    />
                  </Grid>
                  <Grid size={{ xs: 12, md: 3 }}>
                    <Tile
                      label="Growth rate"
                      value={formatRate(growth.BytesPerDay)}
                      caption={`based on the last ${growth.BasisWindowDays ?? '?'} days · ${
                        growth.Confidence ?? 'unknown'
                      } confidence`}
                    />
                  </Grid>
                  <Grid size={{ xs: 12, md: 3 }}>
                    <Card sx={{ height: '100%' }}>
                      <CardContent>
                        <Typography color="text.secondary" variant="overline">
                          Trend
                        </Typography>
                        <Box sx={{ mt: 1 }}>
                          <Chip
                            label={growth.Trend ?? 'Unknown'}
                            color={TREND_COLOUR[growth.Trend] ?? 'default'}
                          />
                        </Box>
                        <Typography color="text.secondary" variant="caption">
                          {growth.StepChanges?.length
                            ? `${growth.StepChanges.length} one-off change(s) excluded from the rate`
                            : 'no one-off events detected'}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid size={{ xs: 12, md: 3 }}>
                    <Tile
                      label="History held"
                      value={`${data.Days ?? 0} days`}
                      caption={
                        growth.FirstDate ? `${growth.FirstDate} to ${growth.LatestDate}` : ''
                      }
                    />
                  </Grid>
                </Grid>

                <Card>
                  <CardHeader
                    title="Consumption over time"
                    subheader="Stacked by workload. Days Microsoft did not report are carried forward from the previous value rather than drawn as zero."
                  />
                  <Divider />
                  <CardContent>
                    <Chart
                      options={chartOptions}
                      series={chartSeries}
                      type="area"
                      height={380}
                    />
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader
                    title="Growth by window"
                    subheader="Several windows rather than one figure: a single cleanup or migration inside the period sets a whole-period rate and then disagrees with everything the client can see."
                  />
                  <Divider />
                  <CardContent>
                    <Grid container spacing={2}>
                      {['30', '90', '180'].map((span) =>
                        growth.Windows?.[span] ? (
                          <Grid size={{ xs: 12, md: 4 }} key={span}>
                            <Tile
                              label={`Last ${span} days`}
                              value={formatRate(growth.Windows[span].BytesPerDay)}
                              caption={`total change ${formatBytes(
                                growth.Windows[span].ChangeBytes,
                              )} since ${growth.Windows[span].FromDate}`}
                            />
                          </Grid>
                        ) : null,
                      )}
                    </Grid>
                    {growth.Note && (
                      <Alert severity="info" sx={{ mt: 2 }}>
                        {growth.Note}
                      </Alert>
                    )}
                  </CardContent>
                </Card>

                <Alert severity="info">
                  Per-mailbox and per-site detail, quota risk and archival candidates are in
                  the <strong>M365 Storage &amp; Usage Report</strong> under Tools &rarr;
                  Reports, which can be emailed on a schedule.
                </Alert>
              </>
            )}

            {trendApi.isError && (
              <Alert severity="error">Could not load storage history for this tenant.</Alert>
            )}
          </Stack>
        </Container>
      </Box>
    </>
  )
}

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>

export default Page
