import { Layout as DashboardLayout } from "../../../layouts/index";
import { CippTablePage } from "../../../components/CippComponents/CippTablePage.jsx";
import CippJsonView from "../../../components/CippFormPages/CippJSONView";

const Page = () => {
  const pageTitle = "Universal Print Printers";

  const offCanvas = {
    children: (row) => <CippJsonView object={row} defaultOpen={true} />,
    size: "xl",
  };

  const simpleColumns = [
    "displayName",
    "manufacturer",
    "model",
    "isShared",
    "isAcceptingJobs",
    "status",
    "registeredDateTime",
  ];

  return (
    <CippTablePage
      title={pageTitle}
      apiUrl="/api/ListPrinters"
      offCanvas={offCanvas}
      simpleColumns={simpleColumns}
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
