// Warns that a tenant has Conditional Access plan rules CIPP does not evaluate (Aspendora fork, Vikunja CIPP-56).
import { Alert } from "@mui/material";
import { ApiGetCall } from "../../api/ApiCall";
import { useSettings } from "../../hooks/use-settings";

export const CippCAPlansWarning = () => {
  const tenant = useSettings().currentTenant;
  const singleTenant = Boolean(tenant) && tenant !== "AllTenants";
  const plans = ApiGetCall({
    url: "/api/ListConditionalAccessPlans",
    data: { tenantFilter: tenant },
    queryKey: `ConditionalAccessPlans-${tenant}`,
    waiting: singleTenant,
  });
  if (!singleTenant || !plans.data?.Warning) return null;
  return <Alert severity="warning">{plans.data.Warning}</Alert>;
};

export default CippCAPlansWarning;
