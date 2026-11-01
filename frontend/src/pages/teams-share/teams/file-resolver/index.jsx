// Teams file resolver (Aspendora fork, Vikunja CIPP-33).
// "I can't open the Teams file" is usually treated as a team-membership problem, but a chat file lives in the
// uploader's OneDrive and a private / shared channel file lives in its own site. /api/ListTeamsFileResolution finds
// where the file really is, who it is shared with, and whether the affected user is covered. Read only: the fix is
// advice plus a link to the CIPP page that applies it.
// Opened with ?url=...&affectedUser=... it runs straight away.
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/router";
import NextLink from "next/link";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Link,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { Grid } from "@mui/system";
import { useForm } from "react-hook-form";
import { Layout as DashboardLayout } from "../../../../layouts/index";
import CippFormComponent from "../../../../components/CippComponents/CippFormComponent";
import { CippFormUserSelector } from "../../../../components/CippComponents/CippFormUserSelector";
import CippButtonCard from "../../../../components/CippCards/CippButtonCard";
import { CippDataTable } from "../../../../components/CippTable/CippDataTable";
import { CippIcons } from "../../../../utils/icon-registry";
import { ApiGetCall } from "../../../../api/ApiCall";
import { useSettings } from "../../../../hooks/use-settings";
import { getCippError } from "../../../../utils/get-cipp-error";

const severityFor = { success: "success", info: "info", warning: "warning", error: "error" };
const accessColor = { Yes: "success", No: "error", Unknown: "default" };
const yesNo = (v) => (v === true ? "yes" : v === false ? "no" : "unknown");
// The user picker returns { label, value }; a typed UPN may arrive as a plain string.
const pickValue = (v) => (v && typeof v === "object" ? v.value ?? "" : v ?? "");

const Fact = ({ label, children }) =>
  children ? (
    <Typography variant="body2">
      <Typography component="span" variant="body2" color="text.secondary">
        {label}:{" "}
      </Typography>
      {children}
    </Typography>
  ) : null;

const ExternalLink = ({ href, children }) =>
  href ? (
    <Link href={href} target="_blank" rel="noopener noreferrer">
      {children ?? href}
    </Link>
  ) : null;

const Page = () => {
  const tenant = useSettings().currentTenant;
  const singleTenant = Boolean(tenant) && tenant !== "AllTenants";
  const router = useRouter();
  const autoRan = useRef(false);
  const [query, setQuery] = useState(null);
  const formControl = useForm({
    defaultValues: { Url: "", AffectedUser: null, SearchUser: null, FileName: "" },
    mode: "onChange",
  });

  const resolution = ApiGetCall({
    url: "/api/ListTeamsFileResolution",
    data: query ?? {},
    queryKey: `TeamsFileResolution-${JSON.stringify(query)}`,
    waiting: Boolean(query),
    retry: 0,
    staleTime: 0,
  });

  const runWith = (params) => setQuery({ tenantFilter: tenant, ...params });

  const runFromForm = () => {
    const v = formControl.getValues();
    const affectedUser = pickValue(v.AffectedUser);
    if (v.Url?.trim()) {
      runWith({ url: v.Url.trim(), affectedUser });
    } else {
      runWith({ userPrincipalName: pickValue(v.SearchUser), fileName: v.FileName?.trim() ?? "", affectedUser });
    }
  };

  // Prefill from a link (?url=&affectedUser=) and run once.
  useEffect(() => {
    if (!router.isReady || autoRan.current || !singleTenant) return;
    const { url, affectedUser } = router.query;
    if (typeof url === "string" && url) {
      autoRan.current = true;
      formControl.setValue("Url", url);
      if (typeof affectedUser === "string" && affectedUser) {
        formControl.setValue("AffectedUser", { label: affectedUser, value: affectedUser });
      }
      runWith({ url, affectedUser: typeof affectedUser === "string" ? affectedUser : "" });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.isReady, router.query.url, singleTenant]);

  if (!singleTenant) {
    return (
      <Box sx={{ px: 3, py: 2 }}>
        <Alert severity="info">Pick a single tenant to resolve a Teams file.</Alert>
      </Box>
    );
  }

  const url = formControl.watch("Url");
  const searchUser = formControl.watch("SearchUser");
  const fileName = formControl.watch("FileName");
  const canRun = Boolean(url?.trim()) || (Boolean(pickValue(searchUser)) && Boolean(fileName?.trim()));

  const r = resolution.isSuccess ? resolution.data : null;
  const location = r?.Location;
  const user = r?.User;
  const diagnosis = r?.Diagnosis;
  const membership = r?.Membership;
  const candidates = Array.isArray(r?.Candidates) ? r.Candidates : [];
  const permissions = Array.isArray(r?.Permissions) ? r.Permissions : [];
  const errors = Array.isArray(r?.Errors) ? r.Errors : [];
  const externalTenants = Array.isArray(membership?.ExternalTenants) ? membership.ExternalTenants : [];
  const sharedWithTeams = Array.isArray(membership?.SharedWithTeams) ? membership.SharedWithTeams : [];
  const errorText = resolution.isError
    ? resolution.error?.response?.data?.Results ?? getCippError(resolution.error)
    : null;

  return (
    <Stack spacing={2} sx={{ px: 3, py: 2 }}>
      <CippButtonCard
        title="Where does this Teams file live, and why can't they open it?"
        CardButton={
          <Button
            variant="contained"
            startIcon={<CippIcons.Search />}
            disabled={resolution.isFetching || !canRun}
            onClick={runFromForm}
          >
            {resolution.isFetching ? "Resolving..." : "Resolve"}
          </Button>
        }
      >
        <Grid container spacing={1.5}>
          <Grid size={{ xs: 12, md: 7 }}>
            <CippFormComponent
              type="textField"
              name="Url"
              label="File link"
              helperText="From Teams (file ... > Copy link), a sharing link, or the browser address bar"
              formControl={formControl}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 5 }}>
            <CippFormUserSelector
              formControl={formControl}
              name="AffectedUser"
              label="User who cannot open it (optional)"
              multiple={false}
              valueField="userPrincipalName"
              creatable={true}
              freeSolo
            />
          </Grid>
          <Grid size={12}>
            <Typography variant="caption" color="text.secondary">
              No link? Search by file name instead (leave the link empty). For a chat file give the person who SENT it.
            </Typography>
          </Grid>
          <Grid size={{ xs: 12, md: 5 }}>
            <CippFormUserSelector
              formControl={formControl}
              name="SearchUser"
              label="Search as user"
              multiple={false}
              valueField="userPrincipalName"
              creatable={true}
              freeSolo
            />
          </Grid>
          <Grid size={{ xs: 12, md: 7 }}>
            <CippFormComponent type="textField" name="FileName" label="File name (or part of it)" formControl={formControl} />
          </Grid>
        </Grid>
        <Typography variant="caption" color="text.secondary">
          Read-only. Chat files live in the uploader&apos;s OneDrive, standard channel files in the team site, and private or
          shared channel files in a separate site with their own membership. The result shows which, every permission on
          the file (sharing-link URLs are never shown), and whether the user is covered.
        </Typography>
      </CippButtonCard>

      {errorText && <Alert severity="error">{String(errorText)}</Alert>}

      {r && diagnosis && (
        <Alert severity={severityFor[diagnosis.Severity] ?? "info"}>
          <Typography variant="subtitle2">{diagnosis.Cause}</Typography>
          {diagnosis.Fix && (
            <Typography variant="body2" sx={{ mt: 0.5 }}>
              <strong>Smallest fix: </strong>
              {diagnosis.Fix}
            </Typography>
          )}
          {Array.isArray(diagnosis.Details) && diagnosis.Details.length > 0 && (
            <Box component="ul" sx={{ mt: 0.5, mb: 0, pl: 3 }}>
              {diagnosis.Details.map((d, i) => (
                <li key={i}>
                  <Typography variant="body2">{d}</Typography>
                </li>
              ))}
            </Box>
          )}
          {diagnosis.FixLink?.Href && (
            <Button
              component={NextLink}
              href={diagnosis.FixLink.Href}
              size="small"
              variant="outlined"
              startIcon={<CippIcons.OpenInNew />}
              sx={{ mt: 1 }}
            >
              {diagnosis.FixLink.Label}
            </Button>
          )}
        </Alert>
      )}

      {errors.length > 0 && <Alert severity="warning">Some data could not be read: {errors.join("; ")}</Alert>}

      {candidates.length > 0 && !r?.Resolved && (
        <Card variant="outlined">
          <CardContent>
            <Typography variant="subtitle1" sx={{ mb: 1 }}>
              Matching files
            </Typography>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Found in</TableCell>
                  <TableCell>Last modified</TableCell>
                  <TableCell />
                </TableRow>
              </TableHead>
              <TableBody>
                {candidates.map((c) => (
                  <TableRow key={`${c.driveId}-${c.itemId}`}>
                    <TableCell>{c.name}</TableCell>
                    <TableCell>{c.foundIn}</TableCell>
                    <TableCell>
                      {c.lastModified}
                      {c.lastModifiedBy ? ` by ${c.lastModifiedBy}` : ""}
                    </TableCell>
                    <TableCell align="right">
                      <Button
                        size="small"
                        disabled={!c.webUrl}
                        onClick={() => {
                          formControl.setValue("Url", c.webUrl);
                          runWith({ url: c.webUrl, affectedUser: pickValue(formControl.getValues().AffectedUser) });
                        }}
                      >
                        Resolve
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {r?.Resolved && location && (
        <Card variant="outlined">
          <CardContent>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
              <Chip size="small" color="primary" label={location.Label} />
              {location.IsChatFile && <Chip size="small" variant="outlined" label="Teams chat file" />}
              {location.Channel?.MembershipType && (
                <Chip size="small" variant="outlined" label={`${location.Channel.MembershipType} channel`} />
              )}
              <Typography variant="subtitle1">{r.Item?.Name}</Typography>
            </Stack>
            <Grid container spacing={1}>
              <Grid size={{ xs: 12, md: 6 }}>
                <Fact label="Path">{r.Item?.Path}</Fact>
                <Fact label="Owner">
                  {location.Owner?.DisplayName}
                  {location.Owner?.Email ? ` (${location.Owner.Email})` : ""}
                  {location.Owner?.State && !["Active", "Group", "Site owner"].includes(location.Owner.State)
                    ? ` - ${location.Owner.State}`
                    : ""}
                </Fact>
                <Fact label="Team">{location.Team?.DisplayName}</Fact>
                <Fact label="Channel">
                  {location.Channel?.DisplayName}
                  {location.Channel?.WebUrl && (
                    <>
                      {" "}
                      <ExternalLink href={location.Channel.WebUrl}>(open in Teams)</ExternalLink>
                    </>
                  )}
                </Fact>
                <Fact label="Matched by">{location.MatchedBy}</Fact>
              </Grid>
              <Grid size={{ xs: 12, md: 6 }}>
                <Fact label="Site">
                  <ExternalLink href={location.SiteUrl} />
                </Fact>
                <Fact label="Library">
                  <ExternalLink href={location.DriveUrl} />
                </Fact>
                <Fact label="Uploaded">
                  {r.Item?.Created}
                  {r.Item?.CreatedBy ? ` by ${r.Item.CreatedBy}` : ""}
                  {r.Item?.CreatedByApp ? ` via ${r.Item.CreatedByApp}` : ""}
                </Fact>
                <Fact label="Last modified">
                  {r.Item?.LastModified}
                  {r.Item?.LastModifiedBy ? ` by ${r.Item.LastModifiedBy}` : ""}
                </Fact>
                <Fact label="Open">
                  <ExternalLink href={r.Item?.WebUrl}>file</ExternalLink>
                </Fact>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {r?.Resolved && user && (
        <Card variant="outlined">
          <CardContent>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
              <Typography variant="subtitle1">{user.UserPrincipalName || user.Requested}</Typography>
              <Chip size="small" color={accessColor[user.HasAccess] ?? "default"} label={`Access: ${user.HasAccess}`} />
              {user.Found && user.UserType && <Chip size="small" variant="outlined" label={user.UserType} />}
              {user.AccountEnabled === false && <Chip size="small" color="error" label="Disabled" />}
            </Stack>
            {Array.isArray(user.AccessVia) && user.AccessVia.length > 0 && (
              <Fact label="Covered by">{user.AccessVia.join("; ")}</Fact>
            )}
            {location?.Team && <Fact label="Team member">{yesNo(user.TeamMember)}</Fact>}
            {location?.Channel && ["private", "shared"].includes(location.Channel.MembershipType) && (
              <Fact label="Channel member">
                {yesNo(user.ChannelMember)}
                {Array.isArray(user.ChannelRoles) && user.ChannelRoles.length > 0 ? ` (${user.ChannelRoles.join(", ")})` : ""}
              </Fact>
            )}
            {user.SharedChannelViaTeam && <Fact label="Shared channel reached through team">{user.SharedChannelViaTeam}</Fact>}
          </CardContent>
        </Card>
      )}

      {r?.Resolved && membership && (
        <Card variant="outlined">
          <CardContent>
            <Typography variant="subtitle1" sx={{ mb: 1 }}>
              Channel membership
            </Typography>
            <Fact label="Channel members">{membership.ChannelMemberCount != null ? String(membership.ChannelMemberCount) : "unknown"}</Fact>
            {sharedWithTeams.length > 0 && (
              <Fact label="Shared with teams">{sharedWithTeams.map((t) => t.displayName).join(", ")}</Fact>
            )}
            {externalTenants.length > 0 && (
              <Box sx={{ mt: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  External members (B2B direct connect). Each tenant must allow direct connect inbound here and outbound in
                  its own cross-tenant access settings.
                </Typography>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Tenant ID</TableCell>
                      <TableCell>Members</TableCell>
                      <TableCell>Direct connect inbound (this tenant)</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {externalTenants.map((t) => (
                      <TableRow key={t.tenantId}>
                        <TableCell>{t.tenantId}</TableCell>
                        <TableCell>{t.members}</TableCell>
                        <TableCell>{t.directConnectInbound}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Box>
            )}
          </CardContent>
        </Card>
      )}

      {r?.Resolved && permissions.length > 0 && (
        <CippDataTable
          title="Permissions on the file"
          data={permissions}
          queryKey={`TeamsFileResolution-${tenant}-${r.Item?.Id}-permissions`}
          simpleColumns={[
            "kind",
            "principal",
            "roles",
            "linkScope",
            "linkType",
            "expires",
            "coversAffectedUser",
          ]}
        />
      )}
    </Stack>
  );
};

Page.getLayout = (page) => <DashboardLayout>{page}</DashboardLayout>;

export default Page;
