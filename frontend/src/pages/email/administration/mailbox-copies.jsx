import { Layout as DashboardLayout } from '../../../layouts/index'
import { CippTablePage } from '../../../components/CippComponents/CippTablePage.jsx'
import { Cancel, PlayArrow } from '@mui/icons-material'

// Mailbox-to-mailbox copies and moves started from the user page ("Copy or move mailbox content").
// Progress is summed live from the copy's chunks. Cancel stops between item groups; Resume re-plans and
// copies only items whose PR_SEARCH_KEY is not already in the destination.
const Page = () => {
  const actions = [
    {
      label: 'Cancel copy',
      type: 'POST',
      icon: <Cancel />,
      url: '/api/ExecMailboxCopy',
      data: { Action: '!Cancel', OperationId: 'OperationId' },
      confirmText:
        'Cancel copying [SourceUser] into [DestinationUser]? Items already copied stay where they are.',
      condition: (row) => ['Planning', 'Copying'].includes(row.Status),
      multiPost: false,
    },
    {
      label: 'Resume (copy only what is missing)',
      type: 'POST',
      icon: <PlayArrow />,
      url: '/api/ExecMailboxCopy',
      data: { Action: '!Resume', OperationId: 'OperationId' },
      confirmText:
        'Resume copying [SourceUser] into [DestinationUser]? CIPP compares the destination with the source and copies only the items that are not there yet, so nothing is duplicated.',
      condition: (row) => ['Cancelled', 'CompletedWithErrors', 'Failed', 'Stalled'].includes(row.Status),
      multiPost: false,
    },
  ]

  return (
    <CippTablePage
      title="Mailbox Copies"
      apiUrl="/api/ListMailboxCopies"
      actions={actions}
      simpleColumns={[
        'Operation',
        'SourceUser',
        'DestinationUser',
        'DestinationFolder',
        'Status',
        'ProgressPercent',
        'ItemsTotal',
        'ItemsCopied',
        'ItemsFailed',
        'AlreadyPresent',
        'Resumes',
        'ArchiveItems',
        'ArchiveDestination',
        'RecentErrors',
        'Message',
        'StartedBy',
        'Started',
        'Finished',
      ]}
    />
  )
}

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>

export default Page
