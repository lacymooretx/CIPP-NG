import { useState } from 'react'
import Head from 'next/head'
import { useRouter } from 'next/router'
import { Layout as DashboardLayout } from '../../../../../layouts/index.js'
import { HeaderedTabbedLayout } from '../../../../../layouts/HeaderedTabbedLayout'
import { useSettings } from '../../../../../hooks/use-settings'
import { ApiGetCall, ApiPostCall } from '../../../../../api/ApiCall'
import { CippHead } from '../../../../../components/CippComponents/CippHead'
import tabOptions from './tabOptions'
import {
  Alert,
  Button,
  Card,
  CardContent,
  CardHeader,
  CircularProgress,
  TextField,
  Typography,
} from '@mui/material'
import { Box, Stack } from '@mui/system'
import GlobalStyles from '@mui/material/GlobalStyles'
import { LockReset, Launch, Print, Send } from '@mui/icons-material'

/*
 * Printable new-hire welcome packet.
 *
 * The markup below deliberately mirrors, element for element and word for word,
 * ~/code/aspendora-branding/templates/welcome-packet.html. That file is the
 * contract; this is one renderer of it. When the copy changes, change it there
 * first and bring it across, or the sheet a CIPP tenant gets and the sheet a
 * hybrid client gets quietly stop being the same document.
 *
 * The stylesheet is the same .pk-* system, served from /public and linked below.
 */

// The app shell must not print. Rather than name CIPP's nav and header classes --
// which are MUI-generated and free to change under us -- hide everything and let
// visibility, which inherits and can be overridden, bring the packet back. The
// packet is lifted to the top-left so the shell's reserved layout does not push
// it down the page.
const printStyles = (
  <GlobalStyles
    styles={{
      '@media print': {
        'body *': { visibility: 'hidden !important' },
        '.packet-preview, .packet-preview *': { visibility: 'visible !important' },
        '.packet-preview': { position: 'absolute !important', left: 0, top: 0, width: '100%' },
      },
    }}
  />
)

const centralTime = (utc) => {
  if (!utc) return null
  try {
    // House rule: operators read times in US Central whatever the source zone.
    return `${new Date(utc).toLocaleString('en-US', {
      timeZone: 'America/Chicago',
      dateStyle: 'medium',
      timeStyle: 'short',
    })} CT`
  } catch {
    return null
  }
}

const Page = () => {
  const router = useRouter()
  const { userId } = router.query
  const settings = useSettings()
  const tenant = settings.currentTenant

  const [confirmingReset, setConfirmingReset] = useState(false)
  const [resetError, setResetError] = useState(null)
  const [welcomeEmailTo, setWelcomeEmailTo] = useState('')
  const [emailResult, setEmailResult] = useState(null)

  const packetRequest = ApiGetCall({
    url: `/api/ExecWelcomePacket?UserID=${userId}&tenantFilter=${tenant}`,
    queryKey: `WelcomePacket-${userId}`,
    waiting: !!userId && !!tenant,
  })

  const packet = packetRequest.data?.Results
  const hasPassword = !!packet?.user?.password

  const resetPassword = ApiPostCall({
    onResult: () => {
      setConfirmingReset(false)
      // The reset writes to IT Glue inside the same call, so the packet can be
      // re-read immediately -- that read is where the new password comes from.
      packetRequest.refetch()
    },
  })

  const handleReset = () => {
    setResetError(null)
    resetPassword.mutate(
      {
        url: '/api/ExecResetPass',
        data: {
          tenantFilter: tenant,
          ID: packet.user.userPrincipalName,
          displayName: packet.user.displayName,
          MustChange: true,
          // The printed sheet IS the delivery channel here, so do not also email
          // or text the secret link -- a dispatched link burns a view and would
          // hand the same credential to a second channel nobody asked for.
          // DocumentInITGlue must stay on: it is how the packet reads it back.
          Delivery: {
            EmailUser: false,
            TextUser: false,
            NotifySupervisor: false,
            DocumentInITGlue: true,
          },
        },
      },
      { onError: (error) => setResetError(error?.response?.data?.Results ?? error.message) },
    )
  }

  const sendEmail = ApiPostCall({})

  const handleSendEmail = () => {
    setEmailResult(null)
    sendEmail.mutate(
      {
        url: '/api/ExecSendWelcomeEmail',
        data: {
          tenantFilter: tenant,
          UserID: packet.user.userPrincipalName,
          RecipientEmail: welcomeEmailTo,
          // The sheet is being printed from this page, so tell the reader to
          // look for the password there rather than for a link that is not coming.
          Delivery: 'printed',
        },
      },
      {
        onSuccess: (r) => {
          setEmailResult({ ok: true, message: r?.data?.Results ?? 'Sent.' })
          setWelcomeEmailTo('')
        },
        onError: (error) =>
          setEmailResult({
            ok: false,
            message: error?.response?.data?.Results ?? error.message,
          }),
      },
    )
  }

  const passwordChanged = centralTime(packet?.passwordUpdatedAtUtc)

  return (
    <HeaderedTabbedLayout
      tabOptions={tabOptions}
      title={packet?.user?.displayName ?? ''}
      isFetching={packetRequest.isFetching}
    >
      <CippHead title="Welcome Packet" />
      <Head>
        {/*
          eslint-disable-next-line @next/next/no-css-tags -- deliberate. The rule
          wants CSS imported so it can be bundled, but a pages-router import of
          global CSS is only legal from _app.js, and routing a one-page print
          stylesheet through _app.js means editing an upstream file and loading
          it on every route. Linking the copy in /public keeps the .pk-* names
          intact and the cost on this page only.
        */}
        <link rel="stylesheet" href="/welcome-packet.css" />
      </Head>
      {printStyles}

      <Box sx={{ p: 3 }} className="no-print">
        <Card>
          <CardHeader title="Printable welcome packet" />
          <CardContent>
            {/* The query is gated on both, so without them nothing loads and
                nothing errors -- an empty card with no explanation. */}
            {!tenant && (
              <Alert severity="info">Select a tenant to build the packet.</Alert>
            )}

            {tenant && packetRequest.isLoading && <CircularProgress size={24} />}

            {packetRequest.isError && (
              <Alert severity="error">
                Could not build the packet: {packetRequest.error?.message}
              </Alert>
            )}

            {packet && (
              <Stack spacing={2}>
                {packet.warning && (
                  <Alert severity={hasPassword ? 'warning' : 'info'}>{packet.warning}</Alert>
                )}

                {resetError && <Alert severity="error">{resetError}</Alert>}

                {emailResult && (
                  <Alert severity={emailResult.ok ? 'success' : 'error'}>{emailResult.message}</Alert>
                )}

                {hasPassword && (
                  <Typography variant="body2" color="text.secondary">
                    Read from IT Glue record <strong>{packet.itGlueName}</strong>
                    {passwordChanged ? `, last changed ${passwordChanged}` : ''}. If{' '}
                    {packet.user.firstName || 'the user'} has already changed it, generate a new one
                    instead.
                  </Typography>
                )}

                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap alignItems="center">
                  <Button
                    variant="contained"
                    startIcon={<Print />}
                    disabled={!hasPassword}
                    onClick={() => window.print()}
                  >
                    Print packet
                  </Button>

                  {!confirmingReset ? (
                    <Button
                      variant="outlined"
                      startIcon={<LockReset />}
                      disabled={resetPassword.isPending}
                      onClick={() => setConfirmingReset(true)}
                    >
                      Generate new password
                    </Button>
                  ) : (
                    <>
                      <Typography variant="body2">
                        Reset {packet.user.displayName}&apos;s password now?
                      </Typography>
                      <Button
                        variant="contained"
                        color="warning"
                        disabled={resetPassword.isPending}
                        onClick={handleReset}
                      >
                        {resetPassword.isPending ? 'Resetting…' : 'Yes, reset it'}
                      </Button>
                      <Button
                        variant="outlined"
                        disabled={resetPassword.isPending}
                        onClick={() => setConfirmingReset(false)}
                      >
                        Cancel
                      </Button>
                    </>
                  )}

                  <TextField
                    size="small"
                    label="Send the welcome email to"
                    placeholder="personal@example.com"
                    value={welcomeEmailTo}
                    onChange={(e) => setWelcomeEmailTo(e.target.value)}
                    helperText="A personal address or their manager — not the new mailbox"
                    sx={{ minWidth: 280 }}
                  />
                  <Button
                    variant="outlined"
                    startIcon={<Send />}
                    disabled={!welcomeEmailTo.includes('@') || sendEmail.isPending}
                    onClick={handleSendEmail}
                  >
                    {sendEmail.isPending ? 'Sending…' : 'Send welcome email'}
                  </Button>

                  {packet.itGlueUrl && (
                    <Button
                      variant="outlined"
                      startIcon={<Launch />}
                      href={packet.itGlueUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      Open in IT Glue
                    </Button>
                  )}
                </Stack>

                {confirmingReset && (
                  <Alert severity="warning">
                    This replaces the password on the live account. Anything already signed in with
                    the old one keeps working until it next asks for credentials. The new password
                    is written to IT Glue and printed here — it is not emailed or texted.
                  </Alert>
                )}

                {hasPassword && (
                  <Typography variant="body2" color="text.secondary">
                    The preview below is the exact printed output — two US&nbsp;Letter pages.
                  </Typography>
                )}
              </Stack>
            )}
          </CardContent>
        </Card>
      </Box>

      {hasPassword && <WelcomePacketSheets packet={packet} />}
    </HeaderedTabbedLayout>
  )
}

/*
 * Kept verbatim against aspendora-branding/templates/welcome-packet.html.
 * Two sections, .packet-page each, in the order they print.
 */
const WelcomePacketSheets = ({ packet }) => {
  const { user, company, brand, support, apps, signInUrl, preparedDate } = packet

  const logo = brand?.logoUrl ? (
    // A plain img, not next/image: the logo is a data URI sized in inches for
    // print, and next/image's optimizer and layout wrapper do neither.
    <img className="pk-logo" src={brand.logoUrl} alt={brand.name} />
  ) : (
    <div className="pk-wordmark">{brand?.name}</div>
  )

  return (
    <div className="packet-preview">
      <div className="packet">
        {/* Page 1: credential sheet */}
        <section className="packet-page">
          <div className="pk-rule" />

          <header className="pk-head">
            {logo}
            <div className="pk-eyebrow">Welcome aboard</div>
          </header>

          <h1 className="pk-title">Welcome, {user.firstName}.</h1>
          <p className="pk-lede">
            Your {company?.name} account is ready. Everything you need for your first sign-in is on
            this page, and step-by-step instructions are on the back.
          </p>

          <div className="pk-card">
            <div className="pk-card-head">Your account</div>
            <dl className="pk-details">
              <dt>Name</dt>
              <dd>{user.displayName}</dd>

              <dt>Email address</dt>
              <dd>{user.email}</dd>

              <dt>Username</dt>
              <dd>{user.userPrincipalName}</dd>

              {user.jobTitle && (
                <>
                  <dt>Job title</dt>
                  <dd>{user.jobTitle}</dd>
                </>
              )}

              {user.department && (
                <>
                  <dt>Department</dt>
                  <dd>{user.department}</dd>
                </>
              )}
            </dl>
          </div>

          <div className="pk-password">
            <div className="pk-password-label">Temporary password</div>
            <div className="pk-password-value">{user.password}</div>
            <div className="pk-password-hint">
              Type it exactly as shown, including the capital letters and hyphens. You will choose
              your own password the first time you sign in.
            </div>
          </div>

          <div className="pk-notice">
            <strong>Keep this page private.</strong> It is the only copy of your temporary password.
            Once you have set your own password, shred this sheet.
          </div>

          <div className="pk-signin">
            <span className="pk-signin-label">Sign in at</span>
            <span className="pk-signin-url">{signInUrl}</span>
          </div>

          <footer className="pk-foot">
            <span>{brand?.name}</span>
            <span>Prepared {preparedDate}</span>
            <span>IT support: {support?.email}</span>
          </footer>
        </section>

        {/* Page 2: getting-started guide */}
        <section className="packet-page pk-guide">
          <div className="pk-rule" />

          <header className="pk-head">
            {logo}
            <div className="pk-eyebrow">Getting started</div>
          </header>

          <h1 className="pk-title pk-title-sm">Your first 15 minutes.</h1>
          <p className="pk-lede">
            Work through these five steps in order. They take about fifteen minutes, and you only
            ever do them once.
          </p>

          <ol className="pk-steps">
            <li>
              <h2>Sign in for the first time</h2>
              <p>
                Open a web browser and go to <strong>{signInUrl}</strong>. Choose <em>Sign in</em>,
                enter <strong>{user.userPrincipalName}</strong>, then the temporary password from
                the front of this packet.
              </p>
            </li>
            <li>
              <h2>Choose your own password</h2>
              <p>
                You will be asked to replace it straight away. Pick something you have never used
                anywhere else — four unrelated words are easier to remember and harder to guess than
                a short password full of symbols.
              </p>
            </li>
            <li>
              <h2>
                Set up Microsoft Authenticator <span className="pk-req">required</span>
              </h2>
              <p>
                Keeps your account safe even if your password is stolen. You need your phone and
                this computer:
              </p>
              <ol className="pk-substeps">
                <li>
                  <strong>Phone:</strong> install <strong>Microsoft Authenticator</strong> from the
                  App Store or Google Play.
                </li>
                <li>
                  <strong>Computer:</strong> go to <strong>aka.ms/mfasetup</strong> — you may land
                  there automatically after step 2.
                </li>
                <li>
                  Choose <strong>Add sign-in method</strong> → <strong>Authenticator app</strong>. A
                  QR code appears on your screen.
                </li>
                <li>
                  <strong>Phone:</strong> tap <strong>+</strong> →{' '}
                  <strong>Work or school account</strong> → <strong>Scan a QR code</strong>, then
                  point it at that code.
                </li>
                <li>Approve the test notification.</li>
              </ol>
            </li>
            <li>
              <h2>Open your everyday apps</h2>
              <p>Sign in to each one with the same email address and your new password:</p>
              <div className="pk-apps">
                {apps?.map((app) => (
                  <div key={app.name}>
                    <strong>{app.name}</strong>
                    <span>{app.description}</span>
                  </div>
                ))}
              </div>
            </li>
            <li>
              <h2>Know how to get help</h2>
              <p>
                {support?.trayAppName ? (
                  <>
                    Find <strong>{support.trayAppName}</strong> in the system tray — the small icons
                    beside the clock, bottom-right of your screen. You may need to click the{' '}
                    <strong>^</strong> arrow to see hidden ones. Click it, choose{' '}
                    <strong>Create Support Ticket</strong>, and describe the problem in your own
                    words; it reaches our service desk with your computer&apos;s details attached.
                    You can also email{' '}
                  </>
                ) : (
                  <>Email </>
                )}
                <strong>{support?.email}</strong>
                {support?.phone && (
                  <>
                    {' '}
                    or call <strong>{support.phone}</strong>
                  </>
                )}
                .{' '}
                {support?.portalUrl && (
                  <>
                    To see where a request stands, sign in to <strong>{support.portalUrl}</strong>.
                  </>
                )}
              </p>
            </li>
          </ol>

          <div className="pk-notice pk-notice-quiet">
            <strong>A note on security.</strong> Nobody from IT will ever ask you for your password.
            If an Authenticator notification appears when you were not signing in, tap <em>Deny</em>{' '}
            and tell us.
          </div>

          <footer className="pk-foot">
            <span>{brand?.name}</span>
            <span>Welcome packet for {user.displayName}</span>
            <span>IT support: {support?.email}</span>
          </footer>
        </section>
      </div>
    </div>
  )
}

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>

export default Page
