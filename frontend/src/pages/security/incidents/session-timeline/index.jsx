// Session timeline (Aspendora fork, Vikunja CIPP-12).
// Pivots one Entra sign-in sessionId across the Unified Audit Log: POST /api/ExecSessionTimelineSearch starts a Graph
// audit log search for the session's user and window (creates a search only, changes no tenant configuration), then
// GET /api/ListSessionTimeline polls it and returns the records whose AADSessionId / SessionId / UniqueTokenId match
// the session, merged with the session's sign-ins, in US Central time.
// Opened with ?sessionId=...&userPrincipalName=... it prefills the form; ?userPrincipalName= alone lists the user's
// recent sessions to pick from.
import { useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/router'
import {
  Alert,
  Box,
  Button,
  Chip,
  LinearProgress,
  Stack,
  Typography,
} from '@mui/material'
import { Grid } from '@mui/system'
import { useForm } from 'react-hook-form'
import { Layout as DashboardLayout } from '../../../../layouts/index'
import CippFormComponent from '../../../../components/CippComponents/CippFormComponent'
import { CippFormUserSelector } from '../../../../components/CippComponents/CippFormUserSelector'
import CippButtonCard from '../../../../components/CippCards/CippButtonCard'
import { CippDataTable } from '../../../../components/CippTable/CippDataTable'
import { CippIcons } from '../../../../utils/icon-registry'
import { ApiGetCall, ApiPostCall } from '../../../../api/ApiCall'
import { useSettings } from '../../../../hooks/use-settings'
import { usePermissions } from '../../../../hooks/use-permissions'
import { getCippError } from '../../../../utils/get-cipp-error'

const guidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
// Highlight labels, in the order they are shown. Keys match Highlights from ListSessionTimeline.
const highlightLabels = [
  ['SignIns', 'sign-ins'],
  ['FailedSignIns', 'failed sign-ins'],
  ['MailItemsRead', 'mails read'],
  ['AttachmentsOpened', 'attachments opened'],
  ['MailsSent', 'mails sent'],
  ['MailsDeleted', 'mails deleted'],
  ['InboxRulesChanged', 'inbox rule changes'],
  ['ForwardingChanged', 'forwarding changes'],
  ['MailboxPermissionsChanged', 'mailbox permission changes'],
  ['FilesAccessed', 'files accessed'],
  ['FilesDownloaded', 'files downloaded'],
  ['FilesChanged', 'files changed'],
  ['FilesDeleted', 'files deleted'],
  ['SharesCreated', 'shares created'],
  ['TeamsMessagesSent', 'Teams messages'],
  ['AppConsents', 'app consents'],
]
// Buckets that mean the session changed or exfiltrated something, shown in a warning colour.
const riskyBuckets = [
  'MailsSent',
  'InboxRulesChanged',
  'ForwardingChanged',
  'MailboxPermissionsChanged',
  'FilesDownloaded',
  'SharesCreated',
  'AppConsents',
  'MailsDeleted',
  'FilesDeleted',
]

const Page = () => {
  const tenant = useSettings().currentTenant
  const singleTenant = Boolean(tenant) && tenant !== 'AllTenants'
  const router = useRouter()
  const { checkPermissions } = usePermissions()
  const canStart = checkPermissions(['Security.Incident.ReadWrite'])
  const [search, setSearch] = useState(null) // { QueryId, SessionId, ... } from ExecSessionTimelineSearch
  const [error, setError] = useState(null)
  const [sessionUser, setSessionUser] = useState(null)
  const prefilled = useRef(false)
  const formControl = useForm({
    defaultValues: { SessionId: '', Days: 7 },
    mode: 'onChange',
  })

  const start = ApiPostCall({ onResult: (result) => setSearch(result) })

  const sessionId = formControl.watch('SessionId')?.trim() ?? ''
  const userValue = formControl.watch('UserPrincipalName')
  const upn = userValue?.value ?? userValue ?? ''

  // Recent sessions for the picked user, so the analyst can choose the suspicious one.
  const sessions = ApiGetCall({
    url: '/api/ListSessionTimeline',
    data: {
      tenantFilter: tenant,
      userPrincipalName: upn,
      days: Number(formControl.watch('Days')) || 7,
    },
    queryKey: `ListSessionTimeline-sessions-${tenant}-${upn}-${formControl.watch('Days')}`,
    waiting: false,
  })

  // Poll the search every 30 s until Microsoft finishes it.
  const [ready, setReady] = useState(false)
  const timeline = ApiGetCall({
    url: '/api/ListSessionTimeline',
    data: {
      tenantFilter: tenant,
      queryId: search?.QueryId,
      sessionId: search?.SessionId,
    },
    queryKey: `ListSessionTimeline-${tenant}-${search?.QueryId}`,
    waiting: Boolean(search?.QueryId),
    staleTime: 0,
    refetchInterval: search?.QueryId && !ready ? 30000 : false,
  })
  const result = timeline.data
  useEffect(() => {
    setReady(
      Boolean(result?.Ready) || ['failed', 'cancelled'].includes(result?.Status)
    )
  }, [result?.Ready, result?.Status])

  useEffect(() => {
    if (!router.isReady || prefilled.current || !singleTenant) return
    prefilled.current = true
    const { sessionId: qsSession, userPrincipalName: qsUpn } = router.query
    if (typeof qsUpn === 'string' && qsUpn) {
      formControl.setValue('UserPrincipalName', { label: qsUpn, value: qsUpn })
    }
    if (typeof qsSession === 'string' && guidPattern.test(qsSession)) {
      formControl.setValue('SessionId', qsSession)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.isReady, singleTenant])

  const startSearch = (overrideSession) => {
    const v = formControl.getValues()
    const id = (overrideSession ?? v.SessionId ?? '').trim()
    setError(null)
    setSearch(null)
    setReady(false)
    setSessionUser(upn || null)
    start.mutate(
      {
        url: '/api/ExecSessionTimelineSearch',
        data: {
          tenantFilter: tenant,
          sessionId: id,
          userPrincipalName: upn || undefined,
          startTime: v.StartTime || undefined,
          endTime: v.EndTime || undefined,
        },
      },
      {
        onError: (e) => setError(e?.response?.data?.Results ?? getCippError(e)),
      }
    )
  }

  if (!singleTenant) {
    return (
      <Box sx={{ px: 3, py: 2 }}>
        <Alert severity="info">
          Pick a single tenant to trace a sign-in session.
        </Alert>
      </Box>
    )
  }

  const sessionRows = Array.isArray(sessions.data?.Results)
    ? sessions.data.Results
    : []
  const rows = Array.isArray(result?.Timeline) ? result.Timeline : []
  const errors = [
    ...(Array.isArray(search?.Errors) ? search.Errors : []),
    ...(Array.isArray(result?.Errors) ? result.Errors : []),
  ]
  const highlights = result?.Highlights ?? {}

  return (
    <Stack spacing={2} sx={{ px: 3, py: 2 }}>
      <CippButtonCard
        title="Trace one sign-in session"
        CardButton={
          <Button
            variant="contained"
            startIcon={<CippIcons.Search />}
            disabled={
              !canStart || start.isPending || !guidPattern.test(sessionId)
            }
            onClick={() => startSearch()}
          >
            {start.isPending ? 'Starting search...' : 'Start search'}
          </Button>
        }
      >
        <Grid container spacing={1.5}>
          <Grid size={{ xs: 12, md: 6 }}>
            <CippFormComponent
              type="textField"
              name="SessionId"
              label="Session ID"
              helperText="The Session ID of a suspicious sign-in (Entra sign-in log, Basic info tab)"
              formControl={formControl}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 6 }}>
            <CippFormUserSelector
              formControl={formControl}
              name="UserPrincipalName"
              label="User (optional; needed to list sessions)"
              multiple={false}
              valueField="userPrincipalName"
              creatable={true}
              freeSolo
            />
          </Grid>
          <Grid size={{ xs: 12, md: 4 }}>
            <CippFormComponent
              type="datePicker"
              name="StartTime"
              label="From (optional)"
              formControl={formControl}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 4 }}>
            <CippFormComponent
              type="datePicker"
              name="EndTime"
              label="To (optional)"
              formControl={formControl}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 4 }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <CippFormComponent
                type="number"
                name="Days"
                label="Days of sessions"
                formControl={formControl}
              />
              <Button
                disabled={!upn || sessions.isFetching}
                onClick={() => sessions.refetch()}
                startIcon={<CippIcons.History />}
              >
                {sessions.isFetching ? 'Reading...' : 'List sessions'}
              </Button>
            </Stack>
          </Grid>
        </Grid>
        <Typography variant="caption" color="text.secondary">
          Starts a Unified Audit Log search for the session&apos;s user over
          Exchange, SharePoint, OneDrive, Teams and Entra logon records, then
          keeps only the records carrying this session (AADSessionId, SessionId
          or one of the session&apos;s token IDs). Without a window it covers
          the session&apos;s first sign-in to two hours after its last.
          Microsoft usually needs 5-20 minutes; this page checks every 30
          seconds. Times are US Central with UTC alongside. Graph activity logs
          are not included (they need Log Analytics). Starting a search needs
          Security.Incident.ReadWrite; it changes nothing in the tenant.
        </Typography>
      </CippButtonCard>

      {sessions.isError && (
        <Alert severity="error">{getCippError(sessions.error)}</Alert>
      )}
      {sessionRows.length > 0 && (
        <CippDataTable
          title={`Recent sessions for ${upn}`}
          data={sessionRows}
          queryKey={`SessionTimeline-sessions-${tenant}-${upn}`}
          simpleColumns={[
            'FirstSignIn',
            'LastSignIn',
            'SignIns',
            'Failures',
            'IPAddresses',
            'Countries',
            'Apps',
            'UserAgent',
            'SessionId',
          ]}
          actions={[
            {
              label: 'Trace this session',
              icon: <CippIcons.Search />,
              noConfirm: true,
              customFunction: (row) => {
                formControl.setValue('SessionId', row.SessionId)
                startSearch(row.SessionId)
              },
            },
          ]}
        />
      )}
      {sessions.isSuccess && sessionRows.length === 0 && (
        <Alert severity="info">
          No interactive sign-in sessions for {upn} in that period.
        </Alert>
      )}

      {error && <Alert severity="error">{String(error)}</Alert>}
      {errors.length > 0 && (
        <Alert severity="warning">{errors.join(' ')}</Alert>
      )}

      {search && (
        <Alert severity={search.QueryId ? 'info' : 'error'}>
          <Typography variant="subtitle2">{search.Message}</Typography>
          <Typography variant="caption" display="block">
            Session {search.SessionId} |{' '}
            {search.UserPrincipalName || sessionUser} |{' '}
            {search.WindowStart?.Display} to {search.WindowEnd?.Display} |{' '}
            {search.SignInCount} sign-ins found
            {search.QueryId ? ` | search ${search.QueryId}` : ''}
          </Typography>
        </Alert>
      )}

      {search?.QueryId && !ready && (
        <Box>
          <Typography variant="body2" color="text.secondary">
            {result?.Message ?? 'Waiting for Microsoft to run the search...'}{' '}
            {result?.Status ? `(status: ${result.Status}` : ''}
            {result?.ApproximateRecordCount
              ? `, about ${result.ApproximateRecordCount} records so far`
              : ''}
            {result?.Status ? ')' : ''}
          </Typography>
          <LinearProgress sx={{ mt: 1 }} />
        </Box>
      )}

      {result && ready && !result.Ready && (
        <Alert severity="error">{result.Message}</Alert>
      )}

      {result?.Ready && (
        <>
          <Alert
            severity={
              riskyBuckets.some((k) => highlights[k] > 0)
                ? 'warning'
                : 'success'
            }
          >
            <Typography variant="subtitle2">{result.Message}</Typography>
            <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
              {result.FirstSeen
                ? `First seen ${result.FirstSeen}, last seen ${result.LastSeen}. `
                : ''}
              Matched by AADSessionId {result.MatchedBy?.AADSessionId ?? 0},
              SessionId {result.MatchedBy?.SessionId ?? 0}, device session{' '}
              {result.MatchedBy?.DeviceSessionId ?? 0}, token ID{' '}
              {result.MatchedBy?.UniqueTokenId ?? 0}.
            </Typography>
            <Stack
              direction="row"
              spacing={1}
              flexWrap="wrap"
              useFlexGap
              sx={{ mt: 1 }}
            >
              {highlightLabels
                .filter(([key]) => highlights[key] > 0)
                .map(([key, label]) => (
                  <Chip
                    key={key}
                    size="small"
                    color={riskyBuckets.includes(key) ? 'warning' : 'default'}
                    label={`${highlights[key]} ${label}`}
                  />
                ))}
            </Stack>
          </Alert>

          <CippDataTable
            title="Session timeline (US Central)"
            data={rows}
            queryKey={`SessionTimeline-${tenant}-${result.QueryId}`}
            simpleColumns={[
              'Time',
              'Workload',
              'Operation',
              'Object',
              'Count',
              'Result',
              'ClientIP',
              'Location',
              'UserAgent',
              'App',
              'MatchedOn',
            ]}
          />
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 6 }}>
              <CippDataTable
                title="By operation"
                data={
                  Array.isArray(result.ByOperation) ? result.ByOperation : []
                }
                queryKey={`SessionTimeline-ops-${tenant}-${result.QueryId}`}
                simpleColumns={['Workload', 'Operation', 'Records', 'Items']}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <CippDataTable
                title="By client IP"
                data={Array.isArray(result.ByIP) ? result.ByIP : []}
                queryKey={`SessionTimeline-ips-${tenant}-${result.QueryId}`}
                simpleColumns={['ClientIP', 'Count', 'FirstSeen', 'LastSeen']}
              />
            </Grid>
          </Grid>
        </>
      )}
    </Stack>
  )
}

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>

export default Page
