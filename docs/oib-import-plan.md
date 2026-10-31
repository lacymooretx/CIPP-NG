# OpenIntuneBaseline (OIB): importing the full Windows release into the CIPP template library

Aspendora fork, Vikunja CIPP-20. Written 2026-10-31. This is a plan only. Nothing here has been imported yet.

## Where things stand (checked read-only on 2026-10-31)

- **Latest OIB Windows release: `windows-v4.0`**, published 2026-09-30 12:53 CDT (17:53 UTC). It is the newest
  `windows-v*` tag. The repo also publishes `macos-v*` and `win365-v*` tags, so GitHub's "latest release" is not a
  reliable signal and the drift check filters on `windows-v*` itself.
- **77 Windows policy files** in that release under `WINDOWS/IntuneManagement/`:

  | Folder | Files | CIPP template type on import |
  |---|---|---|
  | `SettingsCatalog` (47 `SC`, 14 `ES`) | 61 | Catalog |
  | `CompliancePolicies` | 9 | DeviceCompliancePolicies |
  | `UpdatePolicies` (WUfB rings) | 3 | Device |
  | `DriverUpdateProfiles` | 3 | windowsDriverUpdateProfiles |
  | `DeviceConfiguration` (Endpoint Analytics) | 1 | Device |

- `WINDOWS/PolicyManifest.json` (new in 4.0) lists those 77 as `active` and 6 as `deprecated`: the four old
  `Win - OIB - Compliance - U - ...` policies (Defender for Endpoint, Device Health, Device Security, Password),
  `ES - Windows LAPS - D - LAPS Configuration - v3.1` and `SC - Device Security - D - Local Security Policies - v3.0`.
  Every v4.0 policy carries `OIBID:<guid>` in its description, which the drift check uses to match renamed copies.
- **Versions are per policy, not per release.** The 4.0 release still ships files at v3.0 to v3.8; only the policies
  that changed were bumped to v4.0. Compare a policy with the release's copy of that policy, never with "4.0".
- **Already in the CIPP template library:** the 9 `Win - OIB - CP - ... - v4.0` compliance templates
  (Source `SkipToTheEndpoint/OpenIntuneBaseline`, all current), plus the 3 hand-built
  `Aspendora: ... - OIB v4.0 picks` Settings Catalog templates. The picks are not OIB-named, so the drift check
  ignores them.
- **Deployed in tenants:** no `Win - OIB -` policy in any of the 9 tenants. Checked live (Graph) for aspendora.com and
  3endt.com (configuration and compliance policies) and through the CIPP report cache (193 Intune policies across
  all 9 tenants). aspendora.com has only the 3 picks.
- **GitHub access:** the CIPP GitHub extension is not configured, so every GitHub read goes through CIPP's anonymous
  proxy (`cippy.azurewebsites.net`), which is rate-limited. Importing 68 files is 68 reads plus tree reads; do it in
  batches if the proxy starts refusing.

## How the community-repo import works (from the code)

- Endpoint: `POST /api/ExecCommunityRepo`, role `CIPP.TemplateLibrary.ReadWrite`, one file per call.
- Body for one file:

  ```json
  {
    "Action": "ImportTemplate",
    "FullName": "SkipToTheEndpoint/OpenIntuneBaseline",
    "Branch": "windows-v4.0",
    "Path": "WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - SC - Microsoft Edge - D - Security - v4.0.json",
    "Force": false
  }
  ```

  `Branch` is passed straight to GitHub as `?ref=`, so a tag works. Use the tag, not `main`: `main` can hold
  unreleased changes. The Template Library page (`CippTemplateCatalog`) always imports from the repo's default
  branch (`main`), which is why the 2026-10-01 import was done through the API with the tag.
- `Invoke-ExecCommunityRepo` fetches the file (`Get-GitHubFileContents`) and calls `Import-CommunityTemplate`.
  OIB files have no `RowKey`, so they take the Intune path: the type comes from `@odata.id`
  (`configurationPolicies` -> Catalog, `deviceCompliancePolicies` -> DeviceCompliancePolicies,
  `deviceConfigurations` -> Device, `windowsDriverUpdateProfiles`), the JSON is stripped of ids and assignments, and
  `Test-CIPPIntuneTemplate` validates it. A file that fails validation comes back as
  "was not imported: ..." with HTTP 200, so read every result message.
- **Duplicate check is DisplayName + Source.** Re-importing the same file is skipped unless the blob SHA changed (or
  `Force` is true, which overwrites and keeps the GUID and package). Because OIB puts the version in the name, a newer
  release's file (`... - v4.1`) is a *different* template: it is added next to the old one, not over it. Remove the
  superseded template yourself after importing a new release.
- The listing endpoint `GET /api/ListCommunityRepoTemplates?FullName=SkipToTheEndpoint/OpenIntuneBaseline` reads the
  default branch only, so its Imported/UpdateAvailable flags describe `main`, not the release tag.

## Steps

1. **Check what is behind first.** `GET /api/ListOIBDrift?TemplateLibrary=true&RefreshRelease=true`. Expect 9 Current
   and 68 Missing today.
2. **Build the file list** from the release tree, skipping the 9 compliance files already imported:
   `GET https://api.github.com/repos/SkipToTheEndpoint/OpenIntuneBaseline/git/trees/windows-v4.0?recursive=1`, keep
   blobs matching `^WINDOWS/IntuneManagement/.+\.json$`. Do not take `NativeImport/` (macOS/Win365 only) or the
   `WINDOWS365/`, `MACOS/` and `BYOD/` folders.
3. **Decide whether you want all 68.** Several overlap what tenants already run (BitLocker, Defender AV, ASR, LAPS,
   Firewall, Edge, OneDrive, WHfB, WUfB rings, driver rings). Templates in the library are harmless; the risk is only
   at deployment. Importing all of them keeps the library a faithful copy of the release and lets the drift check see
   the full set.
4. **Import** with one `ExecCommunityRepo` call per path (body above, `Branch: "windows-v4.0"`, `Force: false`). A
   short pause between calls avoids the anonymous proxy's rate limit. Keep the responses.
5. **Read back.** `GET /api/ListIntuneTemplates?View=true` and confirm 77 `Win - OIB -` templates with Source
   `SkipToTheEndpoint/OpenIntuneBaseline`. Then `ListOIBDrift?TemplateLibrary=true` should show 77 Current, 0 Missing,
   0 Outdated. Any file reported "was not imported" needs a look at the validation error; don't force it.
6. **Optionally group them**: put the 77 in a template package (for example "OIB windows-v4.0") so a baseline can
   reference the set. Force-reimports keep the package.

## When OIB ships a new release

The weekly `OIBDrift` alert only watches tenants. For the library, run `ListOIBDrift?TemplateLibrary=true` after a
release: Outdated rows are templates to replace, Missing rows are new policies. Import the new files from the new tag
(steps 2 to 5), then delete the Outdated and Retired templates once nothing references them (`ListIntuneTemplates`
shows each template's usage by standards templates).

## The drift check (what was built)

- `Get-CIPPOIBLatestRelease`: highest `windows-v*` release that is not a draft or pre-release, plus its policy list
  (git tree at the tag + `PolicyManifest.json`). Cached 24 h in table `CIPPOIBRelease` (row `OIB/WindowsLatest`);
  served from the stale cache if GitHub cannot be reached.
- `Compare-CIPPOIBVersion` (pure rules) and `Get-CIPPOIBDrift -TenantFilter <t>` / `-TemplateLibrary`.
  States: Current, Outdated (from -> to), Retired (deprecated in or absent from the release), Newer, Unknown (no
  version), Missing (Info only).
- `GET /api/ListOIBDrift?tenantFilter=<t>` or `?TemplateLibrary=true`; `RefreshRelease=true`, `ExcludeMissing=true`.
- Alert `OIBDrift` (weekly, state mode): Outdated and Retired only. Tenants with no OIB policies produce nothing.
