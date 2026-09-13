import { useRouter } from "next/router";
import { Layout as DashboardLayout } from "../../../../layouts/index.js";
import { CippTablePage } from "../../../../components/CippComponents/CippTablePage.jsx";
import { Alert, Button } from "@mui/material";
import { Container } from "@mui/system";
import { ArrowBack } from "@mui/icons-material";
import Link from "next/link";

// Live instances of one Teams policy type for the selected tenant.
// Reached from the catalog page; policyType comes in on the query string.
const Page = () => {
  const router = useRouter();
  const { policyType } = router.query;

  const backButton = (
    <Button component={Link} href="/teams-share/teams/policies" startIcon={<ArrowBack />}>
      Back to policy types
    </Button>
  );

  // router.query is empty on the first render pass, so wait for it rather than
  // firing a request with policyType=undefined.
  if (!router.isReady) return null;

  if (!policyType) {
    return (
      <Container maxWidth={false} sx={{ py: 4 }}>
        <Alert severity="info" action={backButton}>
          No policy type selected. Pick one from the Teams Policies list.
        </Alert>
      </Container>
    );
  }

  return (
    <CippTablePage
      title={`${policyType}`}
      apiUrl="/api/ListTeamsPolicy"
      apiData={{ PolicyType: policyType }}
      queryKey={`ListTeamsPolicy-${policyType}`}
      cardButton={backButton}
      // No simpleColumns on purpose: ConfigAPI property sets differ per policy type and
      // run to 100+ fields, so the table derives its columns from the response.
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
