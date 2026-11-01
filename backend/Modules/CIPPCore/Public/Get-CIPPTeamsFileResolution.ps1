function Get-CIPPTeamsFileResolution {
    <#
    .SYNOPSIS
        Resolve a Teams chat or channel file to where it really lives, who can open it, and the smallest fix.
    .DESCRIPTION
        Read only. Most "I can't open the Teams file" tickets are treated as team-membership problems, but a Teams file
        lives in one of four places and each has its own access model:
          OneDrive           - a file sent in a 1:1 or group chat is stored in the UPLOADER's OneDrive
                               ("Microsoft Teams Chat Files") and shared through a people-specific link with whoever was in
                               the chat at the time. Team membership and later chat membership do not grant access.
          TeamSite           - a standard channel's files are a folder (named after the channel) in the team's site;
                               team membership grants access through the site's Owners / Members groups.
          PrivateChannelSite - a private channel has its own site; only channel members get access, team members do not.
          SharedChannelSite  - a shared channel has its own site; members can come from other teams and, through B2B
                               direct connect, from other tenants.

        Two ways in:
          -Url             a Teams file link (teams.microsoft.com/l/file/...?objectUrl=...), a SharePoint/OneDrive sharing
                           link or a direct file URL. Resolved with Graph /shares/{u!base64url}/driveItem.
          -UserPrincipalName with -FileName
                           searches that user's OneDrive "Microsoft Teams Chat Files" folder and the libraries of the
                           first 25 teams they belong to (10 hits per team, 25 candidates in all). One hit is resolved;
                           several are returned as Candidates for the caller to pick from.

        Returns the location type, site / drive URLs, owner, item path, every permission on the item (sharing-link URLs
        are deliberately not returned: an "anyone" link URL is a credential), whether -AffectedUser is covered and how,
        team versus channel membership for channel files, external (other-tenant) shared-channel members with the B2B
        direct connect setting for their tenant, and a plain-English most-likely cause with the smallest fix and a link
        to the CIPP page that applies it. Every step fails soft into Errors.

        Verified live 2026-11-01 (US Central): /shares resolves both the Doc.aspx?sourcedoc= URL Teams shows and the plain
        path URL; a private or shared channel's filesFolder is the root ("root") of a separate documentLibrary drive whose
        drive.owner is a user, not the team group; a standard channel's filesFolder is a folder named after the channel in
        the team drive, whose owner is the team group; private and shared channel sites both use template TEAMCHANNEL#1,
        so the channel's membershipType (Graph) is the only reliable way to tell them apart; channel members carry tenantId.
        Aspendora fork addition (Vikunja CIPP-33).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding(DefaultParameterSetName = 'Url')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [Parameter(Mandatory = $true, ParameterSetName = 'Url')]
        [string]$Url,
        [Parameter(Mandatory = $true, ParameterSetName = 'Search')]
        [string]$UserPrincipalName,
        [Parameter(Mandatory = $true, ParameterSetName = 'Search')]
        [string]$FileName,
        [string]$AffectedUser
    )

    $Errors = [System.Collections.Generic.List[string]]::new()
    $Graph = 'https://graph.microsoft.com'
    $ChatFolderName = 'Microsoft Teams Chat Files'
    $Central = try { [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { $null }

    function Get-GraphSafe {
        # One Graph GET that records a failure instead of throwing, so one unreadable step never hides the rest.
        param([string]$Uri, [string]$What, [switch]$Paged)
        try {
            if ($Paged) { return , @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -AsApp $true) }
            return (New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -AsApp $true -noPagination $true)
        } catch {
            $Errors.Add("$($What): $((Get-CippException -Exception $_).NormalizedError)")
            return $null
        }
    }

    function Format-Central($Value) {
        # ConvertFrom-Json may already have turned an ISO string into a [datetime]; accept both.
        if (-not $Value) { return $null }
        try {
            $Utc = if ($Value -is [datetime]) { $Value.ToUniversalTime() } else { ([datetimeoffset]$Value).UtcDateTime }
        } catch { return [string]$Value }
        if (-not $Central) { return "$($Utc.ToString('yyyy-MM-dd HH:mm')) UTC" }
        $Local = [System.TimeZoneInfo]::ConvertTimeFromUtc($Utc, $Central)
        "$($Local.ToString('yyyy-MM-dd HH:mm')) $(if ($Central.IsDaylightSavingTime($Local)) { 'CDT' } else { 'CST' }) ($($Utc.ToString('HH:mm')) UTC)"
    }

    function Get-QueryValue([string]$Query, [string]$Name) {
        foreach ($Pair in ($Query.TrimStart('?') -split '&')) {
            $Key, $Value = $Pair -split '=', 2
            if ($Key -and [uri]::UnescapeDataString($Key) -ieq $Name -and $null -ne $Value) {
                return [uri]::UnescapeDataString($Value.Replace('+', ' '))
            }
        }
        return $null
    }

    function Get-Guid([string]$Text) {
        # CSOM serialises GUIDs as "/Guid(...)/"; Graph sends them bare. [regex] keeps $Matches untouched.
        $M = [regex]::Match([string]$Text, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
        if ($M.Success -and $M.Value -ne '00000000-0000-0000-0000-000000000000') { return $M.Value.ToLowerInvariant() }
        return $null
    }

    $Result = [ordered]@{
        Mode          = $PSCmdlet.ParameterSetName
        Input         = [ordered]@{ Url = $Url; UserPrincipalName = $UserPrincipalName; FileName = $FileName; AffectedUser = $AffectedUser }
        ResolvedUrl   = $null
        TeamsLinkHint = $null
        Resolved      = $false
        Item          = $null
        Location      = $null
        Permissions   = @()
        Membership    = $null
        User          = $null
        Candidates    = @()
        Diagnosis     = $null
        Errors        = $null
    }

    # ---- 1. Find the drive item ---------------------------------------------------------------------------------
    $Item = $null
    $ResolveError = $null
    if ($PSCmdlet.ParameterSetName -eq 'Url') {
        $Target = $Url.Trim()
        $Parsed = $null
        # On Linux and macOS a bare "/path" is an absolute file: URI, so the scheme is checked too.
        if (-not [uri]::TryCreate($Target, [System.UriKind]::Absolute, [ref]$Parsed) -or $Parsed.Scheme -notin @('http', 'https')) {
            throw [System.ArgumentException]::new("'$Url' is not a web link. Paste the file link from Teams (... > Copy link) or the browser address bar.")
        }
        # A Teams file link wraps the real SharePoint URL in objectUrl and names the team and channel it came from.
        if ($Parsed.Host -match '(?i)(^|\.)teams\.(microsoft\.com|cloud\.microsoft|live\.com)$') {
            $ObjectUrl = Get-QueryValue $Parsed.Query 'objectUrl'
            $Result.TeamsLinkHint = [ordered]@{
                GroupId   = Get-Guid (Get-QueryValue $Parsed.Query 'groupId')
                ChannelId = Get-QueryValue $Parsed.Query 'threadId'
                TenantId  = Get-Guid (Get-QueryValue $Parsed.Query 'tenantId')
            }
            if (-not $ObjectUrl) {
                throw [System.ArgumentException]::new('This Teams link does not carry the file location (objectUrl). In Teams open the file''s ... menu > Copy link, or open it in the browser and copy that address.')
            }
            $Target = $ObjectUrl
        }
        $Result.ResolvedUrl = $Target
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Target)
        $ShareId = 'u!' + ([System.Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('/', '_').Replace('+', '-'))
        try {
            $Item = New-GraphGetRequest -uri "$Graph/v1.0/shares/$ShareId/driveItem" -tenantid $TenantFilter -AsApp $true -noPagination $true
        } catch {
            $ResolveError = (Get-CippException -Exception $_).NormalizedError
            $Errors.Add("Resolve the link: $ResolveError")
        }
    } else {
        $Needle = $FileName.Trim()
        $Candidates = [System.Collections.Generic.List[object]]::new()
        $Seen = [System.Collections.Generic.HashSet[string]]::new()
        $AddCandidate = {
            param($Hit, [string]$Where)
            if (-not $Hit.id -or $Candidates.Count -ge 25) { return }
            if (-not $Seen.Add("$($Hit.parentReference.driveId)|$($Hit.id)")) { return }
            $Candidates.Add([pscustomobject]@{
                    name                 = [string]$Hit.name
                    foundIn              = $Where
                    webUrl               = [string]$Hit.webUrl
                    driveId              = [string]$Hit.parentReference.driveId
                    itemId               = [string]$Hit.id
                    lastModified         = Format-Central $Hit.lastModifiedDateTime
                    lastModifiedBy       = [string]$Hit.lastModifiedBy.user.displayName
                })
        }
        $EncodedPath = [uri]::EscapeDataString($ChatFolderName)
        $ChatFiles = Get-GraphSafe -Uri "$Graph/v1.0/users/$([uri]::EscapeDataString($UserPrincipalName))/drive/root:/$($EncodedPath):/children?`$select=id,name,webUrl,parentReference,lastModifiedDateTime,lastModifiedBy,file&`$top=999" -What "Read $UserPrincipalName's $ChatFolderName folder"
        foreach ($Hit in @($ChatFiles | Where-Object { $_.file -and ([string]$_.name).IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 })) {
            & $AddCandidate $Hit "$UserPrincipalName's OneDrive ($ChatFolderName)"
        }
        $Joined = Get-GraphSafe -Uri "$Graph/v1.0/users/$([uri]::EscapeDataString($UserPrincipalName))/joinedTeams?`$select=id,displayName" -What "List $UserPrincipalName's teams" -Paged
        $Teams = @($Joined | Where-Object { $_.id } | Select-Object -First 25)
        if ($Teams.Count -gt 0) {
            # drive search takes a quoted string; a quote in the name is doubled, then the whole term is URL-encoded.
            $Q = [uri]::EscapeDataString($Needle.Replace("'", "''"))
            $Requests = foreach ($Team in $Teams) {
                @{ id = [string]$Team.id; method = 'GET'; url = "groups/$($Team.id)/drive/root/search(q='$Q')?`$select=id,name,webUrl,parentReference,lastModifiedDateTime,lastModifiedBy,file&`$top=10" }
            }
            try {
                foreach ($Response in @(New-GraphBulkRequest -Requests @($Requests) -tenantid $TenantFilter -asapp $true)) {
                    if ([int]$Response.status -ge 300) { continue }
                    $TeamName = [string](@($Teams | Where-Object { [string]$_.id -eq [string]$Response.id })[0].displayName)
                    foreach ($Hit in @($Response.body.value | Where-Object { $_.file })) { & $AddCandidate $Hit "Team $TeamName" }
                }
            } catch {
                $Errors.Add("Search team libraries: $((Get-CippException -Exception $_).NormalizedError)")
            }
        }
        $Result.Candidates = $Candidates.ToArray()
        if ($Candidates.Count -eq 1) {
            $Only = $Candidates[0]
            $Result.ResolvedUrl = $Only.webUrl
            try {
                $Item = New-GraphGetRequest -uri "$Graph/v1.0/drives/$($Only.driveId)/items/$($Only.itemId)" -tenantid $TenantFilter -AsApp $true -noPagination $true
            } catch {
                $ResolveError = (Get-CippException -Exception $_).NormalizedError
                $Errors.Add("Read the file: $ResolveError")
            }
        }
    }

    # ---- 2. The affected user (read early: it shapes every later check) -------------------------------------------
    $User = $null
    $UserGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $UserLookupFailed = $false
    if ($AffectedUser) {
        try {
            $User = New-GraphGetRequest -uri "$Graph/v1.0/users/$([uri]::EscapeDataString($AffectedUser.Trim()))?`$select=id,displayName,userPrincipalName,mail,userType,accountEnabled" -tenantid $TenantFilter -AsApp $true -noPagination $true
        } catch {
            $Message = (Get-CippException -Exception $_).NormalizedError
            if (-not [regex]::IsMatch($Message, '(?i)does not exist|not found|ResourceNotFound|404')) { $UserLookupFailed = $true }
            $Errors.Add("Look up $($AffectedUser): $Message")
        }
        if ($User.id) {
            $Groups = Get-GraphSafe -Uri "$Graph/v1.0/users/$($User.id)/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName&`$top=999" -What "Read $($User.userPrincipalName)'s group memberships" -Paged
            foreach ($G in @($Groups)) { if ($G.id) { $null = $UserGroupIds.Add([string]$G.id) } }
        }
        $Result.User = [ordered]@{
            Requested         = $AffectedUser
            Found             = [bool]$User.id
            Id                = [string]$User.id
            DisplayName       = [string]$User.displayName
            UserPrincipalName = [string]$User.userPrincipalName
            Mail              = [string]$User.mail
            UserType          = [string]$User.userType
            AccountEnabled    = $User.accountEnabled
            HasAccess         = 'Unknown'
            AccessVia         = @()
        }
    }

    if (-not $Item.id) {
        $Result.Errors = $Errors.ToArray()
        $Result.Diagnosis = Get-CIPPTeamsFileDiagnosis -Result $Result -ResolveError $ResolveError -TenantFilter $TenantFilter
        return [pscustomobject]$Result
    }
    $Result.Resolved = $true

    # ---- 3. Where the item lives -----------------------------------------------------------------------------------
    $DriveId = [string]$Item.parentReference.driveId
    $ParentPath = [string]$Item.parentReference.path
    $RelPath = if ($ParentPath -like '*root:*') { ($ParentPath -split 'root:', 2)[1].TrimStart('/') } else { '' }
    $TopFolder = if ($RelPath) { ($RelPath -split '/')[0] } else { $null }
    $IsChatFile = ($TopFolder -eq $ChatFolderName) -or ([string]$Item.createdBy.application.displayName -like 'Microsoft Teams*' -and [string]$Item.parentReference.driveType -eq 'business')

    $Result.Item = [ordered]@{
        Id              = [string]$Item.id
        Name            = [string]$Item.name
        Path            = if ($RelPath) { "/$RelPath/$($Item.name)" } else { "/$($Item.name)" }
        WebUrl          = [string]$Item.webUrl
        DriveId         = $DriveId
        IsFolder        = [bool]$Item.folder
        Size            = $Item.size
        CreatedBy       = [string]($Item.createdBy.user.displayName ?? $Item.createdBy.user.email)
        CreatedByEmail  = [string]$Item.createdBy.user.email
        CreatedByApp    = [string]$Item.createdBy.application.displayName
        Created         = Format-Central $Item.createdDateTime
        LastModifiedBy  = [string]$Item.lastModifiedBy.user.displayName
        LastModified    = Format-Central $Item.lastModifiedDateTime
    }

    $Drive = Get-GraphSafe -Uri "$Graph/v1.0/drives/$($DriveId)?`$select=id,name,webUrl,driveType,owner,sharePointIds" -What 'Read the drive'
    $DriveType = [string]($Drive.driveType ?? $Item.parentReference.driveType)
    $SiteUrl = [string]$Drive.sharePointIds.siteUrl
    $HomeTenantId = Get-Guid ([string]$Drive.sharePointIds.tenantId)
    $Location = [ordered]@{
        Type        = 'Unknown'
        Label       = 'Unknown location'
        SiteUrl     = $SiteUrl
        DriveUrl    = [string]$Drive.webUrl
        DriveName   = [string]$Drive.name
        DriveType   = $DriveType
        IsChatFile  = [bool]$IsChatFile
        Owner       = $null
        Team        = $null
        Channel     = $null
        MatchedBy   = $null
    }

    $Team = $null
    $Channel = $null
    if ($DriveType -eq 'business' -or $SiteUrl -match '(?i)-my\.sharepoint\.[a-z.]+/personal/') {
        $Location.Type = 'OneDrive'
        $Location.Label = if ($IsChatFile) { 'Uploader''s OneDrive (Teams chat file)' } else { 'OneDrive' }
        $OwnerRef = $Drive.owner.user
        $Owner = [ordered]@{ DisplayName = [string]$OwnerRef.displayName; Email = [string]$OwnerRef.email; Id = [string]$OwnerRef.id; AccountEnabled = $null; State = 'Unknown' }
        if ($OwnerRef.id) {
            try {
                $OwnerUser = New-GraphGetRequest -uri "$Graph/v1.0/users/$($OwnerRef.id)?`$select=id,userPrincipalName,accountEnabled" -tenantid $TenantFilter -AsApp $true -noPagination $true
                $Owner.AccountEnabled = $OwnerUser.accountEnabled
                $Owner.Email = [string]($OwnerUser.userPrincipalName ?? $Owner.Email)
                $Owner.State = if ($OwnerUser.accountEnabled -eq $false) { 'Disabled' } else { 'Active' }
            } catch {
                $Message = (Get-CippException -Exception $_).NormalizedError
                $Owner.State = if ([regex]::IsMatch($Message, '(?i)does not exist|not found|ResourceNotFound|404')) { 'Deleted' } else { 'Unknown' }
                if ($Owner.State -eq 'Unknown') { $Errors.Add("Read the OneDrive owner: $Message") }
            }
        }
        $Location.Owner = $Owner
    } else {
        $GroupOwnerId = Get-Guid ([string]$Drive.owner.group.id)
        if ($GroupOwnerId) {
            # A group-owned library is a team site (standard channels) or a plain group site.
            $Group = Get-GraphSafe -Uri "$Graph/v1.0/groups/$($GroupOwnerId)?`$select=id,displayName,resourceProvisioningOptions" -What 'Read the site''s group'
            $Team = [ordered]@{ Id = $GroupOwnerId; DisplayName = [string]($Group.displayName ?? $Drive.owner.group.displayName); IsTeam = (@($Group.resourceProvisioningOptions) -contains 'Team') }
            $Location.Owner = [ordered]@{ DisplayName = $Team.DisplayName; Email = [string]$Drive.owner.group.email; Id = $GroupOwnerId; AccountEnabled = $null; State = 'Group' }
            if ($Team.IsTeam) {
                $Location.Type = 'TeamSite'
                $Location.Label = 'Team site (standard channel)'
                if ($TopFolder) {
                    $Channels = Get-GraphSafe -Uri "$Graph/v1.0/teams/$GroupOwnerId/channels?`$select=id,displayName,membershipType,webUrl" -What 'List the team''s channels' -Paged
                    $ByName = @($Channels | Where-Object { [string]$_.displayName -ieq $TopFolder })
                    foreach ($Candidate in $ByName) {
                        $Folder = Get-GraphSafe -Uri "$Graph/v1.0/teams/$GroupOwnerId/channels/$($Candidate.id)/filesFolder?`$select=id,name,parentReference" -What "Read channel $($Candidate.displayName)'s files folder"
                        if ($Folder -and [string]$Folder.parentReference.driveId -eq $DriveId -and [string]$Folder.name -ieq $TopFolder) {
                            $Channel = $Candidate
                            $Location.MatchedBy = 'channel files folder'
                            break
                        }
                    }
                    if (-not $Channel -and $Channels) {
                        # A renamed channel keeps its old folder name, so a folder with no matching channel is common.
                        $Location.MatchedBy = "no channel's files folder is '$TopFolder' (renamed channel, or a folder created in the library)"
                    }
                }
            } else {
                $Location.Type = 'SharePointSite'
                $Location.Label = 'SharePoint site (Microsoft 365 group, no team)'
            }
        } else {
            # A user-owned document library: a private / shared channel site, or an ordinary SharePoint site.
            $ParentTeamIds = [System.Collections.Generic.List[string]]::new()
            $AddTeamId = { param($Id) if ($Id -and -not $ParentTeamIds.Contains($Id)) { $ParentTeamIds.Add($Id) } }
            $Template = $null
            if ($SiteUrl) {
                try {
                    $Site = Get-CIPPSPOSite -TenantFilter $TenantFilter -SiteUrl $SiteUrl
                    $Template = [string]$Site.Template
                    & $AddTeamId (Get-Guid ([string]$Site.RelatedGroupId))
                } catch {
                    $Errors.Add("Read the site's SharePoint properties: $((Get-CippException -Exception $_).NormalizedError)")
                }
            }
            & $AddTeamId $Result.TeamsLinkHint.GroupId
            # A channel site's URL is the team site's URL plus "-<channel>". Try each prefix as a team alias.
            if ($SiteUrl -and $ParentTeamIds.Count -eq 0) {
                $Leaf = ($SiteUrl.TrimEnd('/') -split '/')[-1]
                $Parts = @($Leaf -split '-')
                for ($i = $Parts.Count - 1; $i -ge 1 -and $ParentTeamIds.Count -lt 3; $i--) {
                    $Alias = ($Parts[0..($i - 1)] -join '-').Replace("'", "''")
                    $Found = Get-GraphSafe -Uri "$Graph/v1.0/groups?`$filter=mailNickname eq '$([uri]::EscapeDataString($Alias))'&`$select=id,displayName,resourceProvisioningOptions" -What "Look for the parent team '$Alias'" -Paged
                    foreach ($G in @($Found | Where-Object { @($_.resourceProvisioningOptions) -contains 'Team' })) { & $AddTeamId ([string]$G.id) }
                }
            }
            foreach ($TeamId in $ParentTeamIds) {
                $All = Get-GraphSafe -Uri "$Graph/v1.0/teams/$TeamId/allChannels?`$select=id,displayName,membershipType,webUrl,tenantId" -What 'List the team''s channels' -Paged
                $NonStandard = @($All | Where-Object { [string]$_.membershipType -in @('private', 'shared') } | Select-Object -First 50)
                if ($NonStandard.Count -eq 0) { continue }
                $Requests = foreach ($C in $NonStandard) { @{ id = [string]$C.id; method = 'GET'; url = "teams/$TeamId/channels/$($C.id)/filesFolder?`$select=id,name,parentReference" } }
                try {
                    foreach ($Response in @(New-GraphBulkRequest -Requests @($Requests) -tenantid $TenantFilter -asapp $true)) {
                        if ([int]$Response.status -ge 300) { continue }
                        if ([string]$Response.body.parentReference.driveId -eq $DriveId) {
                            $Channel = @($NonStandard | Where-Object { [string]$_.id -eq [string]$Response.id })[0]
                            break
                        }
                    }
                } catch {
                    $Errors.Add("Match the channel site: $((Get-CippException -Exception $_).NormalizedError)")
                }
                if ($Channel) {
                    $TeamGroup = Get-GraphSafe -Uri "$Graph/v1.0/groups/$($TeamId)?`$select=id,displayName" -What 'Read the parent team'
                    $Team = [ordered]@{ Id = $TeamId; DisplayName = [string]$TeamGroup.displayName; IsTeam = $true }
                    $Location.MatchedBy = 'channel files folder drive'
                    break
                }
            }
            if ($Channel) {
                $Location.Type = if ([string]$Channel.membershipType -eq 'shared') { 'SharedChannelSite' } else { 'PrivateChannelSite' }
                $Location.Label = if ($Location.Type -eq 'SharedChannelSite') { 'Shared channel site' } else { 'Private channel site' }
            } elseif ($Template -like 'TEAMCHANNEL*') {
                $Location.Type = 'PrivateChannelSite'
                $Location.Label = 'Private or shared channel site (parent team not found)'
                $Location.MatchedBy = 'site template only'
            } else {
                $Location.Type = 'SharePointSite'
                $Location.Label = 'SharePoint site'
            }
            if ($Drive.owner.user) {
                $Location.Owner = [ordered]@{ DisplayName = [string]$Drive.owner.user.displayName; Email = [string]$Drive.owner.user.email; Id = [string]$Drive.owner.user.id; AccountEnabled = $null; State = 'Site owner' }
            }
        }
    }
    if ($Team) { $Location.Team = $Team }
    if ($Channel) {
        $Location.Channel = [ordered]@{ Id = [string]$Channel.id; DisplayName = [string]$Channel.displayName; MembershipType = [string]$Channel.membershipType; WebUrl = [string]$Channel.webUrl }
        if (-not $HomeTenantId) { $HomeTenantId = Get-Guid ([string]$Channel.tenantId) }
    }
    $Result.Location = $Location

    # ---- 4. Team and channel membership --------------------------------------------------------------------------
    $TeamMember = $null
    $ChannelMember = $null
    $ChannelRoles = @()
    $SharedViaTeam = $null
    if ($Team -and $User.id) { $TeamMember = $UserGroupIds.Contains([string]$Team.Id) }
    if ($Channel -and $Channel.membershipType -in @('private', 'shared')) {
        $Membership = [ordered]@{
            ChannelMemberCount  = $null
            ExternalMemberCount = $null
            ExternalTenants     = @()
            SharedWithTeams     = @()
        }
        $Members = Get-GraphSafe -Uri "$Graph/v1.0/teams/$($Team.Id)/channels/$($Channel.id)/members" -What 'List channel members' -Paged
        if ($null -ne $Members) {
            $Membership.ChannelMemberCount = @($Members).Count
            if ($User.id) {
                $Me = @($Members | Where-Object { [string]$_.userId -eq [string]$User.id })
                $ChannelMember = $Me.Count -gt 0
                if ($ChannelMember) { $ChannelRoles = @($Me[0].roles) }
            }
            if ($HomeTenantId) {
                $External = @($Members | Where-Object { $_.tenantId -and (Get-Guid ([string]$_.tenantId)) -ne $HomeTenantId })
                $Membership.ExternalMemberCount = $External.Count
                $Sets = @($External | Group-Object { Get-Guid ([string]$_.tenantId) } | Select-Object -First 5)
                # A partner entry with b2bDirectConnectInbound null inherits the default policy (verified live: the
                # default ships as blocked), so the default is read once and used for both missing and inheriting partners.
                $DefaultInbound = $null
                if ($Sets.Count -gt 0) {
                    $Default = Get-GraphSafe -Uri "$Graph/v1.0/policies/crossTenantAccessPolicy/default?`$select=b2bDirectConnectInbound" -What 'Read the default cross-tenant settings'
                    $DefaultInbound = [string]$Default.b2bDirectConnectInbound.usersAndGroups.accessType
                }
                $Membership.ExternalTenants = @(foreach ($Set in $Sets) {
                        $Policy = $null
                        try {
                            $Policy = New-GraphGetRequest -uri "$Graph/v1.0/policies/crossTenantAccessPolicy/partners/$($Set.Name)" -tenantid $TenantFilter -AsApp $true -noPagination $true
                        } catch {
                            # 404 = no partner entry, so the default applies; anything else is worth reporting.
                            $Message = (Get-CippException -Exception $_).NormalizedError
                            if (-not [regex]::IsMatch($Message, '(?i)not found|ResourceNotFound|404')) { $Errors.Add("Read cross-tenant settings for $($Set.Name): $Message") }
                        }
                        $Inbound = [string]$Policy.b2bDirectConnectInbound.usersAndGroups.accessType
                        [pscustomobject]@{
                            tenantId             = $Set.Name
                            members              = $Set.Count
                            partnerEntry         = [bool]$Policy
                            directConnectInbound = if ($Inbound) { $Inbound } elseif ($DefaultInbound) { "$DefaultInbound (default)" } else { 'Unknown' }
                        }
                    })
            }
        }
        if ($Channel.membershipType -eq 'shared') {
            $Shared = Get-GraphSafe -Uri "$Graph/v1.0/teams/$($Team.Id)/channels/$($Channel.id)/sharedWithTeams" -What 'List teams the channel is shared with' -Paged
            $Membership.SharedWithTeams = @(foreach ($S in @($Shared)) {
                    [pscustomobject]@{ id = [string]$S.id; displayName = [string]$S.displayName; tenantId = Get-Guid ([string]$S.tenantId) }
                })
            if ($User.id -and -not $ChannelMember) {
                $Via = @($Membership.SharedWithTeams | Where-Object { $UserGroupIds.Contains([string]$_.id) })
                if ($Via.Count -gt 0) { $SharedViaTeam = [string]$Via[0].displayName }
            }
        }
        $Result.Membership = $Membership
    }

    # ---- 5. Permissions on the item and whether they cover the user --------------------------------------------------
    $Perms = Get-GraphSafe -Uri "$Graph/v1.0/drives/$DriveId/items/$($Item.id)/permissions" -What 'Read the item''s permissions' -Paged
    $PermissionsRead = $null -ne $Perms
    $Via = [System.Collections.Generic.List[string]]::new()
    $UserEmail = [string]($User.mail ?? $User.userPrincipalName)
    $IsMemberUser = [string]$User.userType -ne 'Guest'
    $MatchesUser = {
        param($Identity)
        if (-not $User.id -or -not $Identity) { return $false }
        ([string]$Identity.id -and [string]$Identity.id -eq [string]$User.id) -or
        ($UserEmail -and [string]$Identity.email -and [string]$Identity.email -ieq $UserEmail) -or
        ([string]$Identity.loginName -and [string]$User.userPrincipalName -and ([string]$Identity.loginName).EndsWith("|$($User.userPrincipalName)", [System.StringComparison]::OrdinalIgnoreCase))
    }
    $Rows = foreach ($P in @($Perms)) {
        if (-not $P) { continue }
        $Roles = (@($P.roles) -join ', ')
        $Inherited = [bool]$P.inheritedFrom
        $Covers = $false
        if ($P.link) {
            $Scope = [string]$P.link.scope
            $People = @($P.grantedToIdentitiesV2 | ForEach-Object { $_.user ?? $_.siteUser } | Where-Object { $_ })
            $Expired = $P.expirationDateTime -and ([datetimeoffset]$P.expirationDateTime) -lt [datetimeoffset]::UtcNow
            if (-not $Expired) {
                $Covers = switch ($Scope) {
                    'anonymous' { $true }
                    'organization' { [bool]($User.id -and $IsMemberUser) }
                    'users' { @($People | Where-Object { & $MatchesUser $_ }).Count -gt 0 }
                    default { $false }
                }
            }
            $Kind = 'Sharing link'
            $Principal = switch ($Scope) {
                'anonymous' { 'Anyone with the link' }
                'organization' { 'People in the organisation with the link' }
                'users' { 'Specific people: ' + ((@($People | ForEach-Object { $_.email ?? $_.displayName }) | Select-Object -First 10) -join ', ') + $(if ($People.Count -gt 10) { " (+$($People.Count - 10) more)" }) }
                'existingAccess' { 'People who already have access (grants nothing new)' }
                default { "Link ($Scope)" }
            }
            if ($Covers) { $Via.Add("$Scope sharing link ($Roles)") }
            [pscustomobject]@{
                kind               = $Kind
                principal          = $Principal
                roles              = $Roles
                linkScope          = $Scope
                linkType           = [string]$P.link.type
                expires            = Format-Central $P.expirationDateTime
                expired            = [bool]$Expired
                hasPassword        = [bool]$P.hasPassword
                inherited          = $Inherited
                coversAffectedUser = if ($User.id) { [bool]$Covers } else { $null }
            }
        } else {
            $G = $P.grantedToV2
            $Kind = 'Direct'
            $Principal = $null
            if ($G.group) {
                $Kind = 'Group'
                $Principal = [string]($G.group.displayName ?? $G.group.email)
                # Verified live: a team site grants the group with a claim ending "_o", which means the group's OWNERS,
                # not its members. Only a plain group claim follows membership.
                if ([string]$G.siteUser.loginName -like '*_o') {
                    $Principal = "$Principal (owners)"
                    if ($G.group.id -and $User.id) {
                        $GroupOwners = Get-GraphSafe -Uri "$Graph/v1.0/groups/$($G.group.id)/owners?`$select=id" -What "List owners of $Principal" -Paged
                        $Covers = [bool](@($GroupOwners | Where-Object { [string]$_.id -eq [string]$User.id }).Count -gt 0)
                    }
                } else {
                    $Covers = [bool]($G.group.id -and $UserGroupIds.Contains([string]$G.group.id))
                }
            } elseif ($G.siteGroup) {
                $Kind = 'SharePoint group'
                $Principal = [string]$G.siteGroup.displayName
                # A group-connected or channel site's Owners and Members groups follow team (or channel) membership.
                $Covers = $false
                if ([regex]::IsMatch($Principal, '(?i)\b(Owners|Members)$')) {
                    if ($Location.Type -eq 'TeamSite' -and $TeamMember) { $Covers = $true }
                    if ($Location.Type -in @('PrivateChannelSite', 'SharedChannelSite') -and ($ChannelMember -or $SharedViaTeam)) { $Covers = $true }
                }
            } else {
                $Who = $G.user ?? $G.siteUser ?? $P.grantedTo.user
                $Principal = [string]($Who.displayName ?? $Who.email ?? $P.invitation.email)
                if ($Who.email -and $Who.email -ne $Who.displayName) { $Principal = "$Principal <$($Who.email)>" }
                $Covers = [bool](& $MatchesUser $Who) -or ($UserEmail -and [string]$P.invitation.email -ieq $UserEmail)
                if (@($P.roles) -contains 'owner') { $Kind = 'Owner' }
            }
            if ($Covers) { $Via.Add("$($Kind.ToLower()) $Principal ($Roles)") }
            [pscustomobject]@{
                kind               = $Kind
                principal          = $Principal
                roles              = $Roles
                linkScope          = $null
                linkType           = $null
                expires            = Format-Central $P.expirationDateTime
                expired            = $false
                hasPassword        = $false
                inherited          = $Inherited
                coversAffectedUser = if ($User.id) { [bool]$Covers } else { $null }
            }
        }
    }
    $Result.Permissions = @($Rows)

    if ($Result.User) {
        # No fallback from membership to access: /permissions lists the site's Owners / Members / Visitors groups on an
        # item that inherits (verified live), so a member who is not covered means the item has its own permissions.
        $Result.User.TeamMember = $TeamMember
        $Result.User.ChannelMember = $ChannelMember
        $Result.User.ChannelRoles = $ChannelRoles
        $Result.User.SharedChannelViaTeam = $SharedViaTeam
        $Result.User.AccessVia = $Via.ToArray()
        $Result.User.HasAccess = if (-not $User.id) { 'Unknown' } elseif ($Via.Count -gt 0) { 'Yes' } elseif ($PermissionsRead) { 'No' } else { 'Unknown' }
    }

    $Result.Errors = $Errors.ToArray()
    $Result.Diagnosis = Get-CIPPTeamsFileDiagnosis -Result $Result -ResolveError $ResolveError -TenantFilter $TenantFilter -UserLookupFailed:$UserLookupFailed
    return [pscustomobject]$Result
}
