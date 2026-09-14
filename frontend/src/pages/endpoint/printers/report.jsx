import { Layout as DashboardLayout } from "../../../layouts/index";
import { CippTablePage } from "../../../components/CippComponents/CippTablePage.jsx";

const Page = () => {
  const pageTitle = "Printer Readiness & Usage";

  const simpleColumns = [
    "Tenant",
    "UniversalPrintLicensed",
    "LicensedSeats",
    "PrintersRegistered",
    "SharesRegistered",
    "ConnectorsRegistered",
    "CatalogEntries",
    "PagesPrinted",
    "Errors",
  ];

  return (
    <CippTablePage
      title={pageTitle}
      apiUrl="/api/ListPrinterReport"
      apiData={{ tenantFilter: "AllTenants" }}
      queryKey="PrinterReport"
      tenantInTitle={false}
      simpleColumns={simpleColumns}
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
