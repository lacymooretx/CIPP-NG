import { useMemo } from 'react'
import { Alert, Box, Button, Card, CardContent, Container, Stack, Typography } from '@mui/material'
import {
  Add,
  Delete,
  PlaylistAdd,
  Refresh,
  RemoveCircleOutline,
  RocketLaunch,
  SystemUpdateAlt,
} from '@mui/icons-material'
import { Layout as DashboardLayout } from '../../../layouts/index.js'
import { CippHead } from '../../../components/CippComponents/CippHead'
import { CippDataTable } from '../../../components/CippTable/CippDataTable'
import { CippApiDialog } from '../../../components/CippComponents/CippApiDialog'
import CippJsonView from '../../../components/CippFormPages/CippJSONView'
import { ApiGetCall } from '../../../api/ApiCall'
import { useDialog } from '../../../hooks/use-dialog'
import { useSettings } from '../../../hooks/use-settings'

const updateCategoryOptions = [
  { label: 'Driver', value: 'driver' },
  { label: 'Quality', value: 'quality' },
]

const categoryField = {
  type: 'autoComplete',
  name: 'categories',
  label: 'Update Categories',
  multiple: true,
  creatable: false,
  options: updateCategoryOptions,
}

const deviceIdsField = {
  type: 'textField',
  name: 'deviceIds',
  label: 'Azure AD Device IDs',
  multiline: true,
  minRows: 4,
  disableVariables: true,
}

const Page = () => {
  const pageTitle = 'Autopatch'
  const tenantFilter = useSettings().currentTenant
  const tenantSelected = Boolean(tenantFilter && tenantFilter !== 'AllTenants')
  const queryKey = `ListWindowsAutopatch-${tenantFilter}`
  const onboardDialog = useDialog()
  const addRingDialog = useDialog()
  const enrollDialog = useDialog()

  const autopatch = ApiGetCall({
    url: '/api/ListWindowsAutopatch',
    queryKey,
    data: {
      tenantFilter,
      includeManagedDevices: true,
      includeAudienceMembers: true,
    },
    waiting: tenantSelected,
    toast: true,
    staleTime: 60000,
  })

  const autopatchData = useMemo(() => autopatch.data ?? {}, [autopatch.data])
  const summary = autopatchData.summary ?? {}

  const audienceRows = useMemo(() => {
    const policies = autopatchData.policySummary ?? []
    return (autopatchData.deploymentAudiences ?? []).map((audience) => {
      const audiencePolicies = policies.filter((policy) => policy.audienceId === audience.id)
      return {
        id: audience.id,
        memberCount: audience.memberCount ?? audience.members?.length ?? 0,
        exclusionCount: audience.exclusionCount ?? audience.exclusions?.length ?? 0,
        policyCount: audiencePolicies.length,
        categories: audiencePolicies
          .map((policy) => policy.categories)
          .filter(Boolean)
          .join(', '),
        rawAudience: audience,
      }
    })
  }, [autopatchData.deploymentAudiences, autopatchData.policySummary])

  const policyRows = useMemo(() => {
    return (autopatchData.policySummary ?? []).map((policy) => ({
      id: policy.id,
      audienceId: policy.audienceId,
      categories: policy.categories,
      createdDateTime: policy.rawPolicy?.createdDateTime,
      rawPolicy: policy.rawPolicy,
    }))
  }, [autopatchData.policySummary])

  const enrollmentRows = useMemo(
    () => autopatchData.enrollmentStatus ?? [],
    [autopatchData.enrollmentStatus]
  )

  const metricCards = [
    { label: 'Policies', value: summary.policyCount ?? 0 },
    { label: 'Audiences', value: summary.audienceCount ?? 0 },
    { label: 'Assets', value: summary.assetCount ?? 0 },
    { label: 'Windows Devices', value: summary.managedDeviceCount ?? 0 },
    { label: 'Unenrolled', value: summary.unenrolledDeviceCount ?? 0 },
  ]

  const relatedQueryKeys = [queryKey]

  const policyActions = [
    {
      label: 'Delete Policy',
      icon: <Delete />,
      type: 'POST',
      url: '/api/RemoveAutopatchPolicy',
      data: { policyId: 'id' },
      confirmText: 'Delete Autopatch policy [id]?',
      color: 'danger',
      relatedQueryKeys,
    },
  ]

  const enrollmentActions = [
    {
      label: 'Enroll Device',
      icon: <PlaylistAdd />,
      type: 'POST',
      url: '/api/EnrollAutopatchAsset',
      data: { deviceIds: 'azureADDeviceId' },
      confirmText: 'Enroll [deviceName] into Autopatch?',
      color: 'info',
      condition: (row) => !row.isEnrolled,
      fields: [categoryField],
      defaultvalues: { categories: updateCategoryOptions },
      relatedQueryKeys,
    },
    {
      label: 'Unenroll Device',
      icon: <RemoveCircleOutline />,
      type: 'POST',
      url: '/api/ExecAutopatchUnenroll',
      data: { deviceIds: 'azureADDeviceId' },
      confirmText: 'Unenroll [deviceName] from Autopatch?',
      color: 'danger',
      condition: (row) => row.isEnrolled,
      fields: [categoryField],
      defaultvalues: { categories: updateCategoryOptions },
      relatedQueryKeys,
    },
  ]

  const offCanvas = {
    children: (row) => <CippJsonView object={row} type="intune" defaultOpen={true} />,
    size: 'xl',
  }

  return (
    <>
      <CippHead title={pageTitle} />
      <Container maxWidth={false}>
        <Stack spacing={2}>
          {!tenantSelected && (
            <Alert severity="warning">Select a single tenant to manage Windows Autopatch.</Alert>
          )}

          <Stack direction={{ xs: 'column', md: 'row' }} spacing={1} justifyContent="flex-end">
            <Button
              startIcon={<Refresh />}
              onClick={() => autopatch.refetch()}
              disabled={!tenantSelected || autopatch.isFetching}
            >
              Refresh
            </Button>
            <Button
              startIcon={<RocketLaunch />}
              variant="contained"
              onClick={onboardDialog.handleOpen}
              disabled={!tenantSelected}
            >
              Onboard Tenant
            </Button>
            <Button
              startIcon={<Add />}
              variant="outlined"
              onClick={addRingDialog.handleOpen}
              disabled={!tenantSelected}
            >
              Add Ring
            </Button>
            <Button
              startIcon={<SystemUpdateAlt />}
              variant="outlined"
              onClick={enrollDialog.handleOpen}
              disabled={!tenantSelected}
            >
              Enroll Assets
            </Button>
          </Stack>

          <Box
            sx={{
              display: 'grid',
              gridTemplateColumns: {
                xs: 'repeat(2, minmax(0, 1fr))',
                md: 'repeat(5, minmax(0, 1fr))',
              },
              gap: 2,
            }}
          >
            {metricCards.map((metric) => (
              <Card key={metric.label} sx={{ borderRadius: 1 }}>
                <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                  <Typography variant="overline" color="text.secondary">
                    {metric.label}
                  </Typography>
                  <Typography variant="h5">{metric.value}</Typography>
                </CardContent>
              </Card>
            ))}
          </Box>

          <CippDataTable
            title="Deployment Audiences"
            data={audienceRows}
            simpleColumns={['id', 'memberCount', 'exclusionCount', 'policyCount', 'categories']}
            isFetching={autopatch.isFetching}
            refreshFunction={autopatch}
            offCanvas={offCanvas}
            maxHeightOffset="620px"
          />

          <CippDataTable
            title="Update Policies"
            data={policyRows}
            simpleColumns={['id', 'audienceId', 'categories', 'createdDateTime']}
            actions={policyActions}
            isFetching={autopatch.isFetching}
            refreshFunction={autopatch}
            offCanvas={offCanvas}
            maxHeightOffset="620px"
          />

          <CippDataTable
            title="Enrollment Status"
            data={enrollmentRows}
            simpleColumns={[
              'deviceName',
              'isEnrolled',
              'enrollmentCategories',
              'azureADDeviceId',
              'userPrincipalName',
              'osVersion',
              'lastSyncDateTime',
            ]}
            actions={enrollmentActions}
            isFetching={autopatch.isFetching}
            refreshFunction={autopatch}
            offCanvas={offCanvas}
            maxHeightOffset="620px"
          />
        </Stack>
      </Container>

      <CippApiDialog
        title="Onboard Tenant"
        createDialog={onboardDialog}
        fields={[
          categoryField,
          {
            type: 'switch',
            name: 'force',
            label: 'Force',
          },
        ]}
        defaultvalues={{ categories: updateCategoryOptions, force: false }}
        dialogAfterEffect={() => autopatch.refetch()}
        api={{
          type: 'POST',
          url: '/api/ExecAutopatchOnboard',
          data: {},
          confirmText: 'Create Autopatch audiences and policies for the selected tenant?',
          relatedQueryKeys,
        }}
      />

      <CippApiDialog
        title="Add Autopatch Ring"
        createDialog={addRingDialog}
        fields={[
          {
            type: 'textField',
            name: 'ringName',
            label: 'Ring Name',
            disableVariables: true,
          },
          deviceIdsField,
          categoryField,
        ]}
        defaultvalues={{ ringName: 'Autopatch Ring', categories: updateCategoryOptions }}
        dialogAfterEffect={() => autopatch.refetch()}
        api={{
          type: 'POST',
          url: '/api/AddAutopatchRing',
          data: {},
          confirmText: 'Create an Autopatch audience and policies for these devices?',
          relatedQueryKeys,
        }}
      />

      <CippApiDialog
        title="Enroll Autopatch Assets"
        createDialog={enrollDialog}
        fields={[deviceIdsField, categoryField]}
        defaultvalues={{ categories: updateCategoryOptions }}
        dialogAfterEffect={() => autopatch.refetch()}
        api={{
          type: 'POST',
          url: '/api/EnrollAutopatchAsset',
          data: {},
          confirmText: 'Enroll the listed devices into Autopatch?',
          relatedQueryKeys,
        }}
      />
    </>
  )
}

Page.getLayout = (page) => <DashboardLayout allTenantsSupport={false}>{page}</DashboardLayout>

export default Page
