import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippTablePage } from "../../../../components/CippComponents/CippTablePage.jsx";
import { Visibility } from "@mui/icons-material";

// Catalog of Teams admin policy types, served from Config/TeamsPolicyTypes.json.
// Catalog=true makes no tenant call at all, so this page renders instantly and is
// identical for every tenant — the per-tenant values live on the instances page.
const Page = () => {
  const pageTitle = "Teams Policies";

  const actions = [
    {
      label: "View policy instances",
      link: "/teams-share/teams/policies/instances?policyType=[type]",
      icon: <Visibility />,
      multiPost: false,
    },
  ];

  return (
    <CippTablePage
      title={pageTitle}
      apiUrl="/api/ListTeamsPolicy"
      apiData={{ Catalog: true }}
      queryKey="ListTeamsPolicy-catalog"
      tenantInTitle={false}
      actions={actions}
      simpleColumns={["type", "category", "identity", "premium", "description"]}
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
