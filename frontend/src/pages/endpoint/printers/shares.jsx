import { Layout as DashboardLayout } from "../../../layouts/index";
import { CippIcons } from "../../../utils/icon-registry";
import { CippTablePage } from "../../../components/CippComponents/CippTablePage.jsx";
import CippJsonView from "../../../components/CippFormPages/CippJSONView";

const Page = () => {
  const pageTitle = "Universal Print Shares";

  const actions = [
    {
      label: "Grant access to user",
      type: "POST",
      url: "/api/ExecPrinterShareAccess",
      icon: <CippIcons.Add />,
      data: { ShareId: "id", Action: "!Add", PrincipalType: "!User" },
      fields: [
        {
          type: "autoComplete",
          name: "PrincipalId",
          label: "User",
          multiple: false,
          creatable: false,
          api: {
            url: "/api/ListGraphRequest",
            data: { Endpoint: "users", $select: "id,displayName,userPrincipalName" },
            dataKey: "Results",
            labelField: "userPrincipalName",
            valueField: "id",
            queryKey: "ListUsers-PrinterShare",
          },
        },
      ],
      confirmText: "Grant access to printer share [displayName] for the selected user?",
    },
    {
      label: "Grant access to group",
      type: "POST",
      url: "/api/ExecPrinterShareAccess",
      icon: <CippIcons.Group />,
      data: { ShareId: "id", Action: "!Add", PrincipalType: "!Group" },
      fields: [
        {
          type: "autoComplete",
          name: "PrincipalId",
          label: "Group",
          multiple: false,
          creatable: false,
          api: {
            url: "/api/ListGraphRequest",
            data: { Endpoint: "groups", $select: "id,displayName" },
            dataKey: "Results",
            labelField: "displayName",
            valueField: "id",
            queryKey: "ListGroups-PrinterShare",
          },
        },
      ],
      confirmText: "Grant access to printer share [displayName] for the selected group?",
    },
    {
      label: "Revoke user access",
      type: "POST",
      url: "/api/ExecPrinterShareAccess",
      icon: <CippIcons.Delete />,
      color: "danger",
      data: { ShareId: "id", Action: "!Remove", PrincipalType: "!User" },
      fields: [
        {
          type: "autoComplete",
          name: "PrincipalId",
          label: "User",
          multiple: false,
          creatable: false,
          api: {
            url: "/api/ListGraphRequest",
            data: { Endpoint: "users", $select: "id,displayName,userPrincipalName" },
            dataKey: "Results",
            labelField: "userPrincipalName",
            valueField: "id",
            queryKey: "ListUsers-PrinterShare",
          },
        },
      ],
      confirmText: "Revoke access to printer share [displayName] for the selected user?",
    },
  ];

  const offCanvas = {
    children: (row) => <CippJsonView object={row} defaultOpen={true} />,
    size: "xl",
  };

  const simpleColumns = [
    "displayName",
    "allowAllUsers",
    "isAcceptingJobs",
    "status",
    "createdDateTime",
  ];

  return (
    <CippTablePage
      title={pageTitle}
      apiUrl="/api/ListPrinterShares"
      actions={actions}
      offCanvas={offCanvas}
      simpleColumns={simpleColumns}
    />
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
