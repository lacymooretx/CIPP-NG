import { Layout as DashboardLayout } from '../../layouts/index'
import { CippTablePage } from '../../components/CippComponents/CippTablePage.jsx'

// OneDrive-to-OneDrive copies started from the user page ("Copy OneDrive files to another user").
// The list refreshes progress from SharePoint for any copy still running.
const Page = () => {
  return (
    <CippTablePage
      title="OneDrive Copies"
      apiUrl="/api/ListOneDriveCopies"
      simpleColumns={[
        'SourceUser',
        'DestinationUser',
        'DestinationFolder',
        'Status',
        'ProgressPercent',
        'FilesCreated',
        'Errors',
        'Message',
        'StartedBy',
        'Started',
        'DestinationUrl',
      ]}
    />
  )
}

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>

export default Page
