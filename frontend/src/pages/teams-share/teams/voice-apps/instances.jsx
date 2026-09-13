import { useRouter } from "next/router";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippTablePage } from "../../../../components/CippComponents/CippTablePage.jsx";
import { Alert, Button } from "@mui/material";
import { Container } from "@mui/system";
import { ArrowBack } from "@mui/icons-material";
import Link from "next/link";

// Live objects for one voice-app / assignment route in the selected tenant.
const Page = () => {
  const router = useRouter();
  const { route } = router.query;

  const backButton = (
    <Button component={Link} href="/teams-share/teams/voice-apps" startIcon={<ArrowBack />}>
      Back to routes
    </Button>
  );

  // router.query is empty on the first render pass, so wait for it rather than
  // firing a request with route=undefined.
  if (!router.isReady) return null;

  if (!route) {
    return (
      <Container maxWidth={false} sx={{ py: 4 }}>
        <Alert severity="info" action={backButton}>
          No route selected. Pick one from the Teams Voice Apps list.
        </Alert>
      </Container>
    );
  }

  return (
    <CippTablePage
      title={`${route}`}
      apiUrl="/api/ListTeamsVoiceApp"
      apiData={{ Route: route }}
      queryKey={`ListTeamsVoiceApp-${route}`}
      cardButton={backButton}
      // No simpleColumns on purpose: each route returns a different shape, so the table
      // derives its columns from the response.
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
