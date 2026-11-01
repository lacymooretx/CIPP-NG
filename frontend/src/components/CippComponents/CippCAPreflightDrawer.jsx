// Aspendora fork addition (Vikunja CIPP-5): CA pre-flight (lockout) check for one policy, and the
// gated "Enable policy" action. A failed pre-flight only lets the policy be enabled once the operator
// ticks the override, which the backend logs at Warning with their name.
import { useState } from 'react'
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Checkbox,
  Chip,
  CircularProgress,
  FormControlLabel,
  Stack,
  Typography,
} from '@mui/material'
import { CippIcons } from '../../utils/icon-registry'
import { ApiGetCall, ApiPostCall } from '../../api/ApiCall'
import { CippOffCanvas } from './CippOffCanvas'
import { CippDataTable } from '../CippTable/CippDataTable'
import { CippApiResults } from './CippApiResults'
import { PermissionButton } from '../../utils/permissions'
import { getCippError } from '../../utils/get-cipp-error'

const STATUS_COLOR = { Pass: 'success', Warn: 'warning', Fail: 'error', Info: 'default' }
const StatusChip = ({ status }) => (
  <Chip size="small" label={status} color={STATUS_COLOR[status] || 'default'} variant="outlined" />
)

export const CippCAPreflightDrawer = ({
  policyId,
  policyName,
  policyState,
  tenantFilter,
  visible,
  onClose,
}) => {
  const [override, setOverride] = useState(false)
  const ready = Boolean(visible && policyId && tenantFilter)
  const preflight = ApiGetCall({
    url: '/api/ExecCAPreflight',
    data: { tenantFilter, PolicyId: policyId },
    queryKey: `CAPreflight-${tenantFilter}-${policyId}`,
    waiting: ready,
  })
  const enable = ApiPostCall({ relatedQueryKeys: ['ListConditionalAccessPolicies*', 'CAPreflight*'] })

  const result = preflight.data?.Results
  const checks = Array.isArray(result?.Checks) ? result.Checks : []
  const whatIf = Array.isArray(result?.WhatIf) ? result.WhatIf : []
  const samples = Array.isArray(result?.WouldBeBlocked?.Samples) ? result.WouldBeBlocked.Samples : []
  const errors = Array.isArray(result?.Errors) ? result.Errors : []
  const passed = result?.Passed === true
  const alreadyOn = (result?.CurrentState ?? policyState) === 'enabled'
  const canEnable = Boolean(result) && !alreadyOn && (passed || override)

  const handleClose = () => {
    setOverride(false)
    onClose?.()
  }

  return (
    <CippOffCanvas
      title={`Pre-flight: ${policyName ?? policyId ?? ''}`}
      visible={!!visible}
      onClose={handleClose}
      size="xl"
    >
      <Stack spacing={2} sx={{ mb: 2 }}>
        <Typography variant="body2" color="text.secondary">
          Before this policy is turned On, CIPP checks that the break-glass accounts are excluded,
          that a Global Administrator can still sign in, what happens to you and the break-glass
          accounts (What-If), and that the policy has run in report-only for 7 days. Nothing is
          changed until you press Enable.
        </Typography>
        {preflight.isError && (
          <Alert severity="error">Could not run the pre-flight: {getCippError(preflight.error)}</Alert>
        )}
        {preflight.isFetching && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 3 }}>
            <CircularProgress size={24} />
            <Typography variant="body2" color="text.secondary">
              Reading break-glass accounts, Global Admins, the audit log and report-only sign-ins…
            </Typography>
          </Box>
        )}
        {result && !preflight.isFetching && (
          <>
            <Alert severity={passed ? (result.Status === 'Warn' ? 'warning' : 'success') : 'error'}>
              {passed
                ? result.Status === 'Warn'
                  ? 'Pre-flight passed with warnings. Read them before enabling.'
                  : 'Pre-flight passed.'
                : 'Pre-flight FAILED. Enabling this policy as it stands could lock admins out.'}{' '}
              Checked {result.CheckedUtc ? new Date(result.CheckedUtc).toLocaleString() : ''}.
            </Alert>
            <Card variant="outlined">
              <CardHeader title="Checks" />
              <CardContent>
                <Stack spacing={1.5}>
                  {checks.map((check) => (
                    <Box key={check.Key}>
                      <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                        <StatusChip status={check.Status} />
                        <Typography variant="subtitle2">{check.Check}</Typography>
                      </Stack>
                      <Typography variant="body2" sx={{ mt: 0.5 }}>
                        {check.Message}
                      </Typography>
                      {check.Fix && (
                        <Typography variant="body2" color="text.secondary">
                          Fix: {check.Fix}
                        </Typography>
                      )}
                    </Box>
                  ))}
                </Stack>
              </CardContent>
            </Card>
            {errors.length > 0 && (
              <Alert severity="info">
                Some data could not be read, so the related checks warn rather than pass:
                <ul style={{ margin: 0 }}>
                  {errors.map((error, index) => (
                    <li key={index}>{error}</li>
                  ))}
                </ul>
              </Alert>
            )}
            <CippDataTable
              title="What-If (CIPP evaluation: users, groups, roles and grant controls)"
              noCard={false}
              simple={false}
              isFetching={false}
              data={whatIf}
              simpleColumns={['Role', 'UserPrincipalName', 'Outcome', 'ScopeReason', 'GrantReason']}
              exportEnabled={true}
            />
            {result.WouldBeBlocked?.Collected && (
              <CippDataTable
                title={`Would-be-blocked report-only sign-ins (last ${result.WouldBeBlocked.WindowDays} days, sample)`}
                noCard={false}
                simple={false}
                isFetching={false}
                data={samples}
                simpleColumns={[
                  'createdDateTime',
                  'userPrincipalName',
                  'appDisplayName',
                  'policyResult',
                  'ipAddress',
                  'clientAppUsed',
                ]}
                exportEnabled={true}
              />
            )}
            {!alreadyOn && (
              <Card variant="outlined">
                <CardHeader title="Enable policy" />
                <CardContent>
                  <Stack spacing={1.5}>
                    {!passed && (
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={override}
                            onChange={(event) => setOverride(event.target.checked)}
                          />
                        }
                        label="I have read the failed checks and want to enable the policy anyway (override is logged with my name)."
                      />
                    )}
                    <Box>
                      <PermissionButton
                        requiredPermissions={['Tenant.ConditionalAccess.ReadWrite']}
                        variant="contained"
                        color={passed ? 'primary' : 'error'}
                        startIcon={<CippIcons.Check />}
                        disabled={!canEnable || enable.isPending}
                        onClick={() =>
                          enable.mutate({
                            url: '/api/EditCAPolicy',
                            data: {
                              tenantFilter,
                              GUID: policyId,
                              State: 'enabled',
                              PreflightOverride: !passed && override,
                            },
                          })
                        }
                      >
                        {enable.isPending ? 'Enabling…' : 'Enable policy'}
                      </PermissionButton>
                    </Box>
                    <CippApiResults apiObject={enable} />
                  </Stack>
                </CardContent>
              </Card>
            )}
            <Box>
              <Button
                size="small"
                variant="outlined"
                startIcon={<CippIcons.Refresh />}
                onClick={() => preflight.refetch()}
              >
                Run again
              </Button>
            </Box>
          </>
        )}
      </Stack>
    </CippOffCanvas>
  )
}

export default CippCAPreflightDrawer
