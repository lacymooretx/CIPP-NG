import { Layout as DashboardLayout } from '../../../layouts/index'
import { CippTablePage } from '../../../components/CippComponents/CippTablePage.jsx'
import { Cancel } from '@mui/icons-material'

// Mailbox-to-mailbox copies and moves started from the user page ("Copy or move mailbox content").
// Progress is summed live from the copy's chunks; Cancel stops new chunks from starting.
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
