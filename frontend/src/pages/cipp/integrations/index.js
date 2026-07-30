import { Layout as DashboardLayout } from '../../../layouts/index.js'
import {
  Alert,
  Box,
  Button,
  Card,
  CardActionArea,
  CardActions,
  CardContent,
  Container,
  Skeleton,
  Stack,
  Tooltip,
  Typography,
} from '@mui/material'
import extensions from '../../../data/Extensions'
import { Sync } from '@mui/icons-material'
import { useSettings } from '../../../hooks/use-settings'
import { ApiGetCall, ApiPostCall } from '../../../api/ApiCall'
import { useState } from 'react'
import Link from 'next/link'
import { Grid } from '@mui/system'
import { CippHead } from '../../../components/CippComponents/CippHead'

const Page = () => {
  const settings = useSettings()
  const preferredTheme = settings.currentTheme?.value

  const integrations = ApiGetCall({
    url: '/api/ListExtensionsConfig',
    queryKey: 'Integrations',
    refetchOnMount: false,
    refetchOnReconnect: false,
  })

  // Health probe: a single endpoint that loops every enabled extension server-side
  // and reports reachable/not + tenant mapping counts.
  const autoMap = ApiPostCall({ relatedQueryKeys: ['Integrations', 'IntegrationHealth'] })

  const health = ApiGetCall({
    url: '/api/ListIntegrationHealth',
    queryKey: 'IntegrationHealth',
    refetchOnMount: 'always',
    refetchOnReconnect: false,
  })
  const healthByName = {}
  if (Array.isArray(health?.data?.integrations)) {
    for (const h of health.data.integrations) {
      healthByName[h.name] = h
    }
  }

  return (
    <Container maxWidth={'xl'}>
      <CippHead title="Integrations" noTenant={true} />
      <Stack
        direction="row"
        justifyContent="space-between"
        alignItems="center"
        spacing={4}
        sx={{ mb: 3 }}
      >
        <Typography variant="h4">Integrations</Typography>
        <Stack direction="row" spacing={2}>
          <Button
            variant="outlined"
            color="primary"
            onClick={() => autoMap.mutate({ url: '/api/ExecOnboardTenant', data: { tenantId: 'all', autoMatch: true } })}
            disabled={autoMap.isPending}
          >
            {autoMap.isPending ? 'Auto-mapping...' : 'Auto-map All Tenants'}
          </Button>
          <Button
            variant="contained"
            color="primary"
            startIcon={<Sync />}
            LinkComponent={Link}
            href="/cipp/integrations/sync"
          >
            Sync Jobs
          </Button>
        </Stack>
      </Stack>
      {autoMap.isSuccess && autoMap.data?.summary && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Auto-map result: {autoMap.data.summary.mapped} newly mapped,{' '}
          {autoMap.data.summary.already_mapped} already mapped,{' '}
          {autoMap.data.summary.no_match} no match, {autoMap.data.summary.ambiguous} ambiguous,{' '}
          {autoMap.data.summary.errors} errors.
        </Alert>
      )}
      {autoMap.isError && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Auto-map failed: {autoMap.error?.message || 'unknown error'}
        </Alert>
      )}

      {/* Healthcheck summary */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Integration Health
          </Typography>
          {health.isLoading && (
            <Stack direction="row" spacing={1}>
              <Skeleton variant="rectangular" width={140} height={30} />
              <Skeleton variant="rectangular" width={140} height={30} />
              <Skeleton variant="rectangular" width={140} height={30} />
            </Stack>
          )}
          {health.isSuccess && Array.isArray(health.data?.integrations) && (
            <Stack direction="row" flexWrap="wrap" useFlexGap spacing={1}>
              {health.data.integrations.length === 0 && (
                <Typography variant="body2" color="textSecondary">
                  No integrations enabled yet. Enable one below.
                </Typography>
              )}
              {health.data.integrations.map((h) => (
                <Tooltip key={h.name} title={h.detail || ''} arrow placement="top">
                  <Stack
                    direction="row"
                    alignItems="center"
                    spacing={1}
                    sx={{
                      px: 1.5,
                      py: 0.75,
                      border: '1px solid',
                      borderColor: 'divider',
                      borderRadius: 1,
                    }}
                  >
                    <Box
                      sx={{
                        backgroundColor: h.healthy ? 'success.main' : 'error.main',
                        borderRadius: '50%',
                        width: 10,
                        height: 10,
                      }}
                    />
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      {h.name}
                    </Typography>
                    <Typography variant="caption" color="textSecondary">
                      {h.healthy
                        ? `${h.mappingCount} tenant${h.mappingCount === 1 ? '' : 's'} mapped`
                        : 'unhealthy'}
                    </Typography>
                  </Stack>
                </Tooltip>
              ))}
            </Stack>
          )}
        </CardContent>
      </Card>

      <Grid container spacing={3}>
        {extensions.map((extension) => {
          var logo = extension.logo
          if (preferredTheme === 'dark' && extension?.logoDark) {
            logo = extension.logoDark
          }

          var integrationConfig = integrations?.data?.[extension.id]
          var isEnabled = integrationConfig?.Enabled || extension.id === 'cippapi'
          var status = 'Unconfigured'
          if (integrationConfig && !isEnabled) {
            status = 'Disabled'
          } else if ((integrationConfig && isEnabled) || extension.id === 'cippapi') {
            status = 'Enabled'
          }

          const cardContent = (
            <Card
              align="center"
              sx={{
                display: 'flex',
                flexDirection: 'column',
                height: '100%',
                position: 'relative',
                overflow: 'hidden',
                ...(extension.comingSoon && { opacity: 0.75 }),
              }}
            >
              {extension.comingSoon && (
                <Box
                  sx={{
                    position: 'absolute',
                    top: 28,
                    right: -40,
                    backgroundColor: 'primary.main',
                    color: 'primary.contrastText',
                    padding: '4px 48px',
                    transform: 'rotate(45deg)',
                    fontSize: '0.7rem',
                    fontWeight: 'bold',
                    zIndex: 1,
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                    boxShadow: 1,
                  }}
                >
                  Coming Soon
                </Box>
              )}
              <CardContent>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    height: 80,
                    mb: 1,
                  }}
                >
                  {extension?.logo && (
                    <Box
                      component="img"
                      src={logo}
                      alt={extension.name}
                      sx={{
                        maxWidth: '90%',
                        maxHeight: '100%',
                        objectFit: 'contain',
                      }}
                    />
                  )}
                </Box>
                <Typography variant="body2" color="textSecondary" paragraph>
                  {extension.description}
                </Typography>
              </CardContent>
              <div style={{ flexGrow: 1 }} />
              <CardActions>
                <Stack direction="row" alignItems="center" spacing={1}>
                  {extension.comingSoon ? (
                    <>
                      <Box
                        sx={{
                          backgroundColor: 'info.main',
                          borderRadius: '50%',
                          width: 8,
                          height: 8,
                        }}
                      />
                      <Typography variant="body2">Coming Soon Through Third-Party</Typography>
                    </>
                  ) : (
                    <>
                      {integrations.isSuccess ? (
                        <Box
                          sx={{
                            backgroundColor: isEnabled ? 'success.main' : 'warning.main',
                            borderRadius: '50%',
                            width: 8,
                            height: 8,
                          }}
                        />
                      ) : (
                        <Skeleton variant="circular" width={8} height={8} animation="pulse" />
                      )}

                      <Typography variant="body2">
                        {integrations.isSuccess ? status : 'Loading'}
                      </Typography>
                    </>
                  )}
                </Stack>
              </CardActions>
            </Card>
          )

          return (
            <Grid size={{ md: 6, sm: 12, xl: 3 }} key={extension.id}>
              {extension.comingSoon ? (
                cardContent
              ) : (
                <CardActionArea
                  component={Link}
                  sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    height: '100%',
                  }}
                  href={`/cipp/integrations/configure?id=${extension.id}`}
                >
                  {cardContent}
                </CardActionArea>
              )}
            </Grid>
          )
        })}
      </Grid>
    </Container>
  )
}

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>

export default Page
