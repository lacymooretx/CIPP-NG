import { Layout as DashboardLayout } from "../../../../layouts/index";
import { CippIcons } from "../../../../utils/icon-registry";
import { CippTablePage } from "../../../../components/CippComponents/CippTablePage.jsx";
import CippJsonView from "../../../../components/CippFormPages/CippJSONView";
import { Button } from "@mui/material";
import Link from "next/link";

const Page = () => {
  const pageTitle = "Printer Catalogue";

  const actions = [
    {
      label: "Deploy to Intune",
      type: "POST",
      url: "/api/ExecDeployCatalogPrinter",
      icon: <CippIcons.Sync />,
      data: { id: "id" },
      fields: [
        {
          type: "textField",
          name: "AssignTo",
          label: "Assign to group (name or object id, blank to use the catalogue value)",
        },
      ],
      confirmText:
        "Deploy [Name] to this tenant? Universal Print entries become a settings catalog policy; direct IP and server share entries become an Intune platform script.",
      relatedQueryKeys: "PrinterCatalog",
    },
    {
      label: "Edit",
      link: "/endpoint/printers/catalog/add?id=[id]",
      icon: <CippIcons.Edit />,
    },
    {
      label: "Remove from catalogue",
      type: "POST",
      url: "/api/RemovePrinterCatalogEntry",
      icon: <CippIcons.Delete />,
      color: "danger",
      data: { id: "id" },
      confirmText:
        "Remove [Name] from the catalogue? This only deletes the CIPP record - printers already installed on devices are left alone.",
      relatedQueryKeys: "PrinterCatalog",
    },
  ];

  const offCanvas = {
    children: (row) => <CippJsonView object={row} defaultOpen={true} />,
    size: "xl",
  };

  const simpleColumns = [
    "Name",
    "PrinterType",
    "HostAddress",
    "UNCPath",
    "ShareName",
    "Location",
    "LastDeployed",
  ];

  return (
    <CippTablePage
      title={pageTitle}
      apiUrl="/api/ListPrinterCatalog"
      queryKey="PrinterCatalog"
      actions={actions}
      offCanvas={offCanvas}
      simpleColumns={simpleColumns}
      cardButton={
        <Button component={Link} href="/endpoint/printers/catalog/add" startIcon={<CippIcons.Add />}>
          Add Printer
        </Button>
      }
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
