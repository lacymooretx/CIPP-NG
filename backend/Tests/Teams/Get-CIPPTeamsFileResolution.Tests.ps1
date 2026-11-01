# Pester tests for Get-CIPPTeamsFileResolution / Get-CIPPTeamsFileDiagnosis (Vikunja CIPP-33).
# Synthetic tenant (contoso / fabrikam), made-up ids. Response shapes copy what Graph returned live on 2026-11-01:
# a channel site's filesFolder is the root of its own drive, the team site lists Owners / Members / Visitors site groups
# on each item, the team group is granted with an "_o" (owners) claim, and channel members carry tenantId.
# Pins: location classification, chat-file vs team vs channel coverage, the "_o" owners claim, link URLs never
# returned, the Teams objectUrl unwrap and u! encoding, B2B direct connect falling back to the default policy, search
# mode, and fail-soft errors.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Modules = Join-Path $RepoRoot 'Modules'
    foreach ($Name in 'Get-CIPPTeamsFileResolution.ps1', 'Get-CIPPTeamsFileDiagnosis.ps1') {
        $Path = Get-ChildItem -Path $Modules -Recurse -Filter $Name -File | Select-Object -First 1 -ExpandProperty FullName
        if (-not $Path) { throw "Could not locate $Name" }
        . $Path
    }

    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $AsApp, $noPagination, [switch]$ComplexFilter) }
    function New-GraphBulkRequest { [CmdletBinding()] param($Requests, $tenantid, $asapp) }
    function Get-CIPPSPOSite { [CmdletBinding()] param($TenantFilter, $SiteUrl) }
    function Get-CippException { [CmdletBinding()] param($Exception) @{ NormalizedError = "$Exception" } }

    # Everything goes through JSON so the objects have the shape (and the re-typed dates) Graph responses have.
    function script:J($Object) { $Object | ConvertTo-Json -Depth 10 | ConvertFrom-Json }

    $script:HomeTenant = '11111111-1111-1111-1111-111111111111'
    $script:Partner = '22222222-2222-2222-2222-222222222222'
    $script:TeamId = 'aaaaaaaa-0000-0000-0000-000000000001'
    $script:UserId = 'bbbbbbbb-0000-0000-0000-000000000001'
    $script:OwnerId = 'bbbbbbbb-0000-0000-0000-000000000002'
    $script:Upn = 'pat@contoso.com'

    function script:New-Fixture {
        $script:F = @{
            Item = $null; ShareThrows = $null; Drive = $null; Permissions = @(); Users = @{}; UserGroups = @()
            Groups = @{}; GroupOwners = @{}; Channels = @(); AllChannels = @(); FilesFolder = @{}; ChannelMembers = @()
            SharedWithTeams = @(); Partners = @{}; DefaultPolicy = $null; Spo = $null; ByAlias = @(); ChatFiles = @()
            Joined = @(); Search = @{}
        }
        $script:F.Users[$script:Upn] = J @{ id = $script:UserId; displayName = 'Pat'; userPrincipalName = $script:Upn; mail = $script:Upn; userType = 'Member'; accountEnabled = $true }
        $script:F.Users[$script:OwnerId] = J @{ id = $script:OwnerId; userPrincipalName = 'sam@contoso.com'; accountEnabled = $true }
    }

    function script:Set-ChatFile([switch]$SharedWithPat) {
        $script:F.Item = J @{
            id = 'ITEM1'; name = 'Budget.xlsx'; webUrl = 'https://contoso-my.sharepoint.com/personal/sam_contoso_com/_layouts/15/Doc.aspx?sourcedoc=x'
            createdDateTime = '2026-10-30T15:00:00Z'; lastModifiedDateTime = '2026-10-31T15:00:00Z'
            createdBy = @{ user = @{ displayName = 'Sam'; email = 'sam@contoso.com' }; application = @{ displayName = 'Microsoft Teams Web Client' } }
            parentReference = @{ driveType = 'business'; driveId = 'b!ONEDRIVE'; path = '/drives/b!ONEDRIVE/root:/Microsoft Teams Chat Files' }
            file = @{ mimeType = 'x' }
        }
        $script:F.Drive = J @{ id = 'b!ONEDRIVE'; name = 'OneDrive'; driveType = 'business'; webUrl = 'https://contoso-my.sharepoint.com/personal/sam_contoso_com/Documents'
            owner = @{ user = @{ id = $script:OwnerId; displayName = 'Sam'; email = 'sam@contoso.com' } }
            sharePointIds = @{ siteUrl = 'https://contoso-my.sharepoint.com/personal/sam_contoso_com'; tenantId = $script:HomeTenant } }
        $People = @(@{ user = @{ id = 'cccccccc-0000-0000-0000-000000000009'; displayName = 'Lee'; email = 'lee@contoso.com' } })
        if ($SharedWithPat) { $People += @{ user = @{ id = $script:UserId; displayName = 'Pat'; email = $script:Upn } } }
        $script:F.Permissions = @(
            (J @{ id = 'p-owner'; roles = @('owner'); grantedToV2 = @{ user = @{ id = $script:OwnerId; displayName = 'Sam'; email = 'sam@contoso.com' } } }),
            (J @{ id = 'p-link'; roles = @('read'); grantedToIdentitiesV2 = $People; link = @{ scope = 'users'; type = 'view'; webUrl = 'https://contoso-my.sharepoint.com/:x:/g/SECRET' } })
        )
    }

    function script:Set-TeamSiteFile([string[]]$PatGroups = @(), [switch]$UniquePermissions) {
        $script:F.Item = J @{
            id = 'ITEM2'; name = 'Plan.docx'; webUrl = 'https://contoso.sharepoint.com/sites/Sales/Shared%20Documents/Deals/Plan.docx'
            createdBy = @{ user = @{ displayName = 'Sam' } }
            parentReference = @{ driveType = 'documentLibrary'; driveId = 'b!TEAM'; path = '/drives/b!TEAM/root:/Deals/2026' }
        }
        $script:F.Drive = J @{ id = 'b!TEAM'; name = 'Documents'; driveType = 'documentLibrary'; webUrl = 'https://contoso.sharepoint.com/sites/Sales/Shared%20Documents'
            owner = @{ group = @{ id = $script:TeamId; displayName = 'Sales'; email = 'sales@contoso.com' } }
            sharePointIds = @{ siteUrl = 'https://contoso.sharepoint.com/sites/Sales'; tenantId = $script:HomeTenant } }
        $script:F.Groups[$script:TeamId] = J @{ id = $script:TeamId; displayName = 'Sales'; resourceProvisioningOptions = @('Team') }
        $script:F.Channels = @(J @{ id = '19:deals@thread.tacv2'; displayName = 'Deals'; membershipType = 'standard'; webUrl = 'https://teams.example/deals' })
        $script:F.FilesFolder['19:deals@thread.tacv2'] = J @{ id = 'FOLDER'; name = 'Deals'; parentReference = @{ driveId = 'b!TEAM' } }
        $script:F.UserGroups = @($PatGroups | ForEach-Object { J @{ id = $_; displayName = 'g' } })
        $script:F.Permissions = if ($UniquePermissions) {
            @(J @{ id = 'p1'; roles = @('write'); grantedToV2 = @{ user = @{ id = 'cccccccc-0000-0000-0000-000000000009'; displayName = 'Lee'; email = 'lee@contoso.com' } } })
        } else {
            @(
                (J @{ id = 'p-own'; roles = @('owner'); grantedToV2 = @{ siteGroup = @{ displayName = 'Sales Owners'; id = '3' } } }),
                (J @{ id = 'p-mem'; roles = @('write'); grantedToV2 = @{ siteGroup = @{ displayName = 'Sales Members'; id = '5' } } }),
                (J @{ id = 'p-grp'; roles = @('owner'); grantedToV2 = @{ group = @{ id = $script:TeamId; displayName = 'Sales' }; siteUser = @{ loginName = "c:0o.c|federateddirectoryclaimprovider|$($script:TeamId)_o" } } })
            )
        }
    }

    function script:Set-ChannelSiteFile([string]$MembershipType = 'private', [switch]$PatInChannel, [switch]$PatInTeam, [switch]$ExternalMember, [switch]$PartnerAllows) {
        $script:F.Item = J @{
            id = 'ITEM3'; name = 'Payroll.xlsx'; webUrl = 'https://contoso.sharepoint.com/sites/Sales-Finance/Shared%20Documents/Payroll.xlsx'
            parentReference = @{ driveType = 'documentLibrary'; driveId = 'b!CHANNEL'; path = '/drives/b!CHANNEL/root:' }
        }
        $script:F.Drive = J @{ id = 'b!CHANNEL'; name = 'Documents'; driveType = 'documentLibrary'; webUrl = 'https://contoso.sharepoint.com/sites/Sales-Finance/Shared%20Documents'
            owner = @{ user = @{ id = $script:OwnerId; displayName = 'Sam' } }
            sharePointIds = @{ siteUrl = 'https://contoso.sharepoint.com/sites/Sales-Finance'; tenantId = $script:HomeTenant } }
        # CSOM leaves RelatedGroupId empty here so the URL-prefix fallback is exercised.
        $script:F.Spo = [pscustomobject]@{ Template = 'TEAMCHANNEL#1'; RelatedGroupId = '/Guid(00000000-0000-0000-0000-000000000000)/' }
        $script:F.ByAlias = @(J @{ id = $script:TeamId; displayName = 'Sales'; resourceProvisioningOptions = @('Team') })
        $script:F.Groups[$script:TeamId] = J @{ id = $script:TeamId; displayName = 'Sales'; resourceProvisioningOptions = @('Team') }
        $script:F.AllChannels = @(
            (J @{ id = '19:general@thread.tacv2'; displayName = 'General'; membershipType = 'standard'; tenantId = $script:HomeTenant }),
            (J @{ id = '19:other@thread.tacv2'; displayName = 'Other'; membershipType = 'private'; tenantId = $script:HomeTenant }),
            (J @{ id = '19:finance@thread.tacv2'; displayName = 'Finance'; membershipType = $MembershipType; tenantId = $script:HomeTenant; webUrl = 'https://teams.example/finance' })
        )
        $script:F.FilesFolder['19:other@thread.tacv2'] = J @{ id = 'R1'; name = 'root'; parentReference = @{ driveId = 'b!OTHER' } }
        $script:F.FilesFolder['19:finance@thread.tacv2'] = J @{ id = 'R2'; name = 'root'; parentReference = @{ driveId = 'b!CHANNEL' } }
        $Members = @(J @{ userId = $script:OwnerId; roles = @('owner'); tenantId = $script:HomeTenant })
        if ($PatInChannel) { $Members += J @{ userId = $script:UserId; roles = @(); tenantId = $script:HomeTenant } }
        if ($ExternalMember) { $Members += J @{ userId = 'dddddddd-0000-0000-0000-000000000001'; roles = @(); tenantId = $script:Partner } }
        $script:F.ChannelMembers = $Members
        $script:F.UserGroups = if ($PatInTeam) { @(J @{ id = $script:TeamId }) } else { @() }
        $script:F.DefaultPolicy = J @{ b2bDirectConnectInbound = @{ usersAndGroups = @{ accessType = 'blocked' } } }
        if ($PartnerAllows) { $script:F.Partners[$script:Partner] = J @{ tenantId = $script:Partner; b2bDirectConnectInbound = @{ usersAndGroups = @{ accessType = 'allowed' } } } }
        $script:F.Permissions = @(
            (J @{ id = 'p-mem'; roles = @('write'); grantedToV2 = @{ siteGroup = @{ displayName = 'Sales-Finance Members'; id = '5' } } })
        )
    }
}

Describe 'Get-CIPPTeamsFileResolution' {
    BeforeEach {
        New-Fixture
        $script:Calls = [System.Collections.Generic.List[string]]::new()
        Mock New-GraphGetRequest {
            $script:Calls.Add($uri)
            if ($uri -like '*/shares/*') { if ($script:F.ShareThrows) { throw $script:F.ShareThrows }; return $script:F.Item }
            if ($uri -like '*/items/*/permissions*') { return $script:F.Permissions }
            if ($uri -like '*/drives/*/items/*') { return $script:F.Item }
            if ($uri -match '/drives/[^/?]+\?') { return $script:F.Drive }
            if ($uri -like '*/transitiveMemberOf/*') { return $script:F.UserGroups }
            if ($uri -like '*/joinedTeams*') { return $script:F.Joined }
            if ($uri -like '*/drive/root:/*') { return $script:F.ChatFiles }
            if ($uri -like '*crossTenantAccessPolicy/default*') { return $script:F.DefaultPolicy }
            if ($uri -like '*crossTenantAccessPolicy/partners/*') {
                $T = ($uri -split '/')[-1]
                if ($script:F.Partners.ContainsKey($T)) { return $script:F.Partners[$T] }
                throw 'Resource not found (404)'
            }
            if ($uri -like '*/sharedWithTeams*') { return $script:F.SharedWithTeams }
            if ($uri -like '*/channels/*/members*') { return $script:F.ChannelMembers }
            if ($uri -like '*/filesFolder*') { return $script:F.FilesFolder[[regex]::Match($uri, 'channels/([^/]+)/filesFolder').Groups[1].Value] }
            if ($uri -like '*/allChannels*') { return $script:F.AllChannels }
            if ($uri -like '*/channels?*') { return $script:F.Channels }
            if ($uri -like '*/owners?*') { return @($script:F.GroupOwners[[regex]::Match($uri, 'groups/([^/]+)/owners').Groups[1].Value]) }
            if ($uri -like '*/groups?*mailNickname*') { return $script:F.ByAlias }
            $G = [regex]::Match($uri, '/groups/([^/?]+)\?')
            if ($G.Success) { if ($script:F.Groups.ContainsKey($G.Groups[1].Value)) { return $script:F.Groups[$G.Groups[1].Value] }; throw 'Resource does not exist (404)' }
            $U = [regex]::Match($uri, '/users/([^/?]+)\?')
            if ($U.Success) {
                $Key = [uri]::UnescapeDataString($U.Groups[1].Value)
                if ($script:F.Users.ContainsKey($Key)) { return $script:F.Users[$Key] }
                throw "Resource '$Key' does not exist (404)"
            }
            throw "unexpected GET $uri"
        }
        Mock New-GraphBulkRequest {
            foreach ($R in $Requests) {
                if ($R.url -like '*filesFolder*') {
                    $Body = $script:F.FilesFolder[$R.id]
                    [pscustomobject]@{ id = $R.id; status = $(if ($Body) { 200 } else { 404 }); body = $Body }
                } else {
                    [pscustomobject]@{ id = $R.id; status = 200; body = (J @{ value = @($script:F.Search[$R.id]) }) }
                }
            }
        }
        Mock Get-CIPPSPOSite { if ($script:F.Spo) { return $script:F.Spo }; throw 'spo unavailable' }
    }

    Context 'chat file in the uploader''s OneDrive' {
        It 'classifies it, names the uploader, and blames the people-specific link when the user is not on it' {
            Set-ChatFile
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso-my.sharepoint.com/personal/sam_contoso_com/Documents/Microsoft%20Teams%20Chat%20Files/Budget.xlsx' -AffectedUser $script:Upn
            $R.Resolved | Should -BeTrue
            $R.Location.Type | Should -Be 'OneDrive'
            $R.Location.IsChatFile | Should -BeTrue
            $R.Location.Owner.DisplayName | Should -Be 'Sam'
            $R.Location.Owner.State | Should -Be 'Active'
            $R.Item.Path | Should -Be '/Microsoft Teams Chat Files/Budget.xlsx'
            $R.User.HasAccess | Should -Be 'No'
            $R.Diagnosis.Code | Should -Be 'OneDriveNotShared'
            $R.Diagnosis.FixLink.Href | Should -BeLike '/teams-share/onedrive*'
            ($R.Permissions | Where-Object linkScope -EQ 'users').principal | Should -BeLike '*lee@contoso.com*'
        }

        It 'never returns a sharing-link URL' {
            Set-ChatFile
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso-my.sharepoint.com/x' -AffectedUser $script:Upn
            ($R | ConvertTo-Json -Depth 10) | Should -Not -BeLike '*SECRET*'
        }

        It 'reports access through the people-specific link and points at sign-in instead' {
            Set-ChatFile -SharedWithPat
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso-my.sharepoint.com/x' -AffectedUser $script:Upn
            $R.User.HasAccess | Should -Be 'Yes'
            @($R.User.AccessVia)[0] | Should -BeLike 'users sharing link*'
            $R.Diagnosis.Code | Should -Be 'HasAccess'
            $R.Diagnosis.FixLink.Href | Should -BeLike '/identity/reports/signin-explainer*'
        }

        It 'flags a deleted uploader' {
            Set-ChatFile
            $script:F.Users.Remove($script:OwnerId)
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso-my.sharepoint.com/x' -AffectedUser $script:Upn
            $R.Location.Owner.State | Should -Be 'Deleted'
            $R.Diagnosis.Code | Should -Be 'OwnerGone'
        }

        It 'describes the location without an affected user' {
            Set-ChatFile
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso-my.sharepoint.com/x'
            $R.User | Should -BeNullOrEmpty
            $R.Diagnosis.Code | Should -Be 'LocationOnly'
            $R.Diagnosis.Cause | Should -BeLike '*Sam''s OneDrive*'
            @($R.Permissions)[0].coversAffectedUser | Should -BeNullOrEmpty
        }
    }

    Context 'Teams links' {
        It 'unwraps objectUrl and encodes it as u! base64url without padding' {
            Set-ChatFile
            $Real = 'https://contoso-my.sharepoint.com/personal/sam_contoso_com/Documents/Microsoft Teams Chat Files/Budget.xlsx'
            $Link = "https://teams.microsoft.com/l/file/ABC?tenantId=$($script:HomeTenant)&fileType=xlsx&objectUrl=$([uri]::EscapeDataString($Real))&groupId=$($script:TeamId)&threadId=19%3Ax%40thread.v2"
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url $Link
            $R.ResolvedUrl | Should -Be $Real
            $R.TeamsLinkHint.GroupId | Should -Be $script:TeamId
            $R.TeamsLinkHint.ChannelId | Should -Be '19:x@thread.v2'
            $Expected = 'u!' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Real)).TrimEnd('=').Replace('/', '_').Replace('+', '-')
            @($script:Calls | Where-Object { $_ -like '*/shares/*' })[0] | Should -BeLike "*/shares/$Expected/driveItem"
        }

        It 'rejects a Teams link with no objectUrl and a non-web value as argument errors' {
            { Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://teams.microsoft.com/l/channel/19%3Ax/General' } | Should -Throw -ExceptionType ([System.ArgumentException])
            { Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url '/just/a/path' } | Should -Throw -ExceptionType ([System.ArgumentException])
        }

        It 'explains an unreadable link as another organisation''s file, fail-soft' {
            $script:F.ShareThrows = 'accessDenied (403)'
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://fabrikam.sharepoint.com/:w:/s/x/abc' -AffectedUser $script:Upn
            $R.Resolved | Should -BeFalse
            $R.Diagnosis.Code | Should -Be 'OtherTenantOrNoAccess'
            @($R.Errors).Count | Should -BeGreaterThan 0
        }

        It 'explains a missing item' {
            $script:F.ShareThrows = 'itemNotFound (404)'
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x'
            $R.Diagnosis.Code | Should -Be 'NotFound'
        }
    }

    Context 'standard channel file in the team site' {
        It 'finds the channel by its files folder and says to add a non-member to the team' {
            Set-TeamSiteFile
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x' -AffectedUser $script:Upn
            $R.Location.Type | Should -Be 'TeamSite'
            $R.Location.Team.DisplayName | Should -Be 'Sales'
            $R.Location.Channel.DisplayName | Should -Be 'Deals'
            $R.User.TeamMember | Should -BeFalse
            $R.Diagnosis.Code | Should -Be 'NotTeamMember'
            $R.Diagnosis.FixLink.Href | Should -BeLike "/identity/administration/groups/edit?groupId=$($script:TeamId)*"
        }

        It 'covers a team member through the site Members group' {
            Set-TeamSiteFile -PatGroups @($script:TeamId)
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x' -AffectedUser $script:Upn
            $R.User.HasAccess | Should -Be 'Yes'
            @($R.User.AccessVia) -join ';' | Should -BeLike '*Sales Members*'
            $R.Diagnosis.Code | Should -Be 'HasAccess'
        }

        It 'treats the "_o" group claim as owners only' {
            Set-TeamSiteFile -PatGroups @($script:TeamId)
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x' -AffectedUser $script:Upn
            $Grant = $R.Permissions | Where-Object kind -EQ 'Group'
            $Grant.principal | Should -Be 'Sales (owners)'
            $Grant.coversAffectedUser | Should -BeFalse
        }

        It 'blames unique permissions, not membership, when a team member is not covered' {
            Set-TeamSiteFile -PatGroups @($script:TeamId) -UniquePermissions
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x' -AffectedUser $script:Upn
            $R.User.TeamMember | Should -BeTrue
            $R.User.HasAccess | Should -Be 'No'
            $R.Diagnosis.Code | Should -Be 'UniquePermissions'
            $R.Diagnosis.FixLink.Href | Should -BeLike '/teams-share/sharepoint*'
        }
    }

    Context 'private and shared channel sites' {
        It 'finds the parent team from the site URL and matches the channel by its drive' {
            Set-ChannelSiteFile -PatInTeam
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x' -AffectedUser $script:Upn
            $R.Location.Type | Should -Be 'PrivateChannelSite'
            $R.Location.Channel.DisplayName | Should -Be 'Finance'
            $R.Location.Team.Id | Should -Be $script:TeamId
            $R.User.TeamMember | Should -BeTrue
            $R.User.ChannelMember | Should -BeFalse
            $R.Diagnosis.Code | Should -Be 'NotChannelMember'
        }

        It 'covers a private channel member through the channel site Members group' {
            Set-ChannelSiteFile -PatInTeam -PatInChannel
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x' -AffectedUser $script:Upn
            $R.User.HasAccess | Should -Be 'Yes'
        }

        It 'uses the SharePoint RelatedGroupId when CSOM supplies it' {
            Set-ChannelSiteFile -PatInTeam
            $script:F.Spo = [pscustomobject]@{ Template = 'TEAMCHANNEL#1'; RelatedGroupId = "/Guid($($script:TeamId))/" }
            $script:F.ByAlias = @()
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x' -AffectedUser $script:Upn
            $R.Location.Channel.DisplayName | Should -Be 'Finance'
            @($script:Calls | Where-Object { $_ -like '*mailNickname*' }).Count | Should -Be 0
        }

        It 'lists external shared-channel tenants with B2B direct connect, falling back to the default policy' {
            Set-ChannelSiteFile -MembershipType 'shared' -ExternalMember
            $script:F.SharedWithTeams = @(J @{ id = 'eeeeeeee-0000-0000-0000-000000000001'; displayName = 'Ops'; tenantId = $script:HomeTenant })
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x' -AffectedUser $script:Upn
            $R.Location.Type | Should -Be 'SharedChannelSite'
            $R.Membership.ExternalMemberCount | Should -Be 1
            @($R.Membership.ExternalTenants)[0].tenantId | Should -Be $script:Partner
            @($R.Membership.ExternalTenants)[0].directConnectInbound | Should -Be 'blocked (default)'
            @($R.Membership.SharedWithTeams)[0].displayName | Should -Be 'Ops'
            $R.Diagnosis.Code | Should -Be 'NotChannelMember'
            # A 404 for a missing partner entry is expected, not an error.
            @($R.Errors | Where-Object { $_ -like '*cross-tenant*' }).Count | Should -Be 0
        }

        It 'reports a partner-specific direct connect setting' {
            Set-ChannelSiteFile -MembershipType 'shared' -ExternalMember -PartnerAllows
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x'
            @($R.Membership.ExternalTenants)[0].directConnectInbound | Should -Be 'allowed'
        }

        It 'covers a shared-channel user through a team the channel is shared with' {
            Set-ChannelSiteFile -MembershipType 'shared'
            $script:F.SharedWithTeams = @(J @{ id = 'eeeeeeee-0000-0000-0000-000000000001'; displayName = 'Ops'; tenantId = $script:HomeTenant })
            $script:F.UserGroups = @(J @{ id = 'eeeeeeee-0000-0000-0000-000000000001' })
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x' -AffectedUser $script:Upn
            $R.User.SharedChannelViaTeam | Should -Be 'Ops'
            $R.User.HasAccess | Should -Be 'Yes'
        }

        It 'still classifies a channel site from its template when the team cannot be found, and keeps going when SPO fails' {
            Set-ChannelSiteFile
            $script:F.ByAlias = @()
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x'
            $R.Location.Type | Should -Be 'PrivateChannelSite'
            $R.Location.MatchedBy | Should -Be 'site template only'

            $script:F.Spo = $null
            $R2 = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso.sharepoint.com/x'
            $R2.Location.Type | Should -Be 'SharePointSite'
            @($R2.Errors | Where-Object { $_ -like '*SharePoint properties*' }).Count | Should -Be 1
        }
    }

    Context 'affected user edge cases' {
        It 'says an unknown user is external' {
            Set-ChatFile
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso-my.sharepoint.com/x' -AffectedUser 'someone@fabrikam.com'
            $R.User.Found | Should -BeFalse
            $R.Diagnosis.Code | Should -Be 'ExternalUser'
        }

        It 'stops at a disabled user' {
            Set-ChatFile
            $script:F.Users[$script:Upn].accountEnabled = $false
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso-my.sharepoint.com/x' -AffectedUser $script:Upn
            $R.Diagnosis.Code | Should -Be 'UserDisabled'
        }

        It 'reports Unknown, not No, when permissions cannot be read' {
            Set-ChatFile
            $script:F.Permissions = $null
            Mock New-GraphGetRequest { throw 'permissions blocked' } -ParameterFilter { $uri -like '*/permissions*' }
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -Url 'https://contoso-my.sharepoint.com/x' -AffectedUser $script:Upn
            $R.User.HasAccess | Should -Be 'Unknown'
            $R.Diagnosis.Code | Should -Be 'AccessUnknown'
        }
    }

    Context 'search mode' {
        It 'resolves the single match from the chat files folder and team libraries' {
            Set-ChatFile
            $script:F.ChatFiles = @(
                (J @{ id = 'ITEM1'; name = 'Budget.xlsx'; webUrl = 'https://contoso-my.sharepoint.com/b'; file = @{ mimeType = 'x' }; parentReference = @{ driveId = 'b!ONEDRIVE' } }),
                (J @{ id = 'F1'; name = 'Budget folder'; folder = @{}; parentReference = @{ driveId = 'b!ONEDRIVE' } })
            )
            $script:F.Joined = @(J @{ id = $script:TeamId; displayName = 'Sales' })
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -UserPrincipalName 'sam@contoso.com' -FileName 'budget'
            @($R.Candidates).Count | Should -Be 1
            $R.Resolved | Should -BeTrue
            $R.Location.Type | Should -Be 'OneDrive'
        }

        It 'returns several matches as candidates without resolving' {
            $script:F.ChatFiles = @(J @{ id = 'A'; name = 'Budget.xlsx'; file = @{ mimeType = 'x' }; parentReference = @{ driveId = 'b!ONEDRIVE' } })
            $script:F.Joined = @(J @{ id = $script:TeamId; displayName = 'Sales' })
            $script:F.Search[$script:TeamId] = @(J @{ id = 'B'; name = 'Budget 2026.xlsx'; file = @{ mimeType = 'x' }; parentReference = @{ driveId = 'b!TEAM' } })
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -UserPrincipalName 'sam@contoso.com' -FileName 'budget'
            @($R.Candidates).Count | Should -Be 2
            ($R.Candidates | Where-Object itemId -EQ 'B').foundIn | Should -Be 'Team Sales'
            $R.Resolved | Should -BeFalse
            $R.Diagnosis.Code | Should -Be 'MultipleMatches'
        }

        It 'explains that chat files live with the sender when nothing matches' {
            $R = Get-CIPPTeamsFileResolution -TenantFilter 'contoso.com' -UserPrincipalName 'pat@contoso.com' -FileName 'nothing'
            @($R.Candidates).Count | Should -Be 0
            $R.Diagnosis.Code | Should -Be 'NotFound'
            ($R.Diagnosis.Details -join ' ') | Should -BeLike '*SENT*'
        }
    }
}
