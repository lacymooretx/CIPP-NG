import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippTablePage } from "../../../../components/CippComponents/CippTablePage.jsx";
import { Visibility } from "@mui/icons-material";

// Catalog of Teams ConfigAPI routes outside /Skype.Policy/configurations — call queues,
// auto attendants, schedules, resource accounts, group policy assignments.
// Served from Config/TeamsVoiceAppRoutes.json; Catalog=true makes no tenant call.
// The "verified" column records what a live GET actually returned (200 = confirmed
// reachable, empty = not yet probed), because this is an undocumented surface.
const Page = () => {
  const pageTitle = "Teams Voice Apps & Assignments";

  const actions = [
    {
      label: "View in tenant",
      link: "/teams-share/teams/voice-apps/instances?route=[key]",
      icon: <Visibility />,
      multiPost: false,
    },
  ];

  return (
    <CippTablePage
      title={pageTitle}
      apiUrl="/api/ListTeamsVoiceApp"
      apiData={{ Catalog: true }}
      queryKey="ListTeamsVoiceApp-catalog"
      tenantInTitle={false}
      actions={actions}
      simpleColumns={["key", "category", "verified", "path", "description"]}
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
