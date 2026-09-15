import { Layout as DashboardLayout } from "../../../layouts/index";
import { CippTablePage } from "../../../components/CippComponents/CippTablePage.jsx";

const Page = () => {
  const pageTitle = "Printer Deployment Status";

  const simpleColumns = [
    "Printer",
    "DeviceName",
    "RunState",
    "ErrorCode",
    "LastStateUpdate",
    "Message",
  ];

  return (
    <CippTablePage
      title={pageTitle}
      apiUrl="/api/ListPrinterDeploymentStatus"
      queryKey="PrinterDeploymentStatus"
      simpleColumns={simpleColumns}
      initialFilters={[
        { filterName: "Failures only", value: [{ id: "RunState", value: "fail" }], type: "column" },
      ]}
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
