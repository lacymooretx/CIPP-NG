function Get-CIPPTeamsFileDiagnosis {
    <#
    .SYNOPSIS
        Turn a Get-CIPPTeamsFileResolution result into the most likely cause and the smallest fix.
    .DESCRIPTION
        First matching rule wins. The fix is advice plus a link to the existing CIPP page that applies it; nothing is
        changed here. Aspendora fork addition (Vikunja CIPP-33).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param($Result, [string]$ResolveError, [string]$TenantFilter, [switch]$UserLookupFailed)

    $L = $Result.Location
    $U = $Result.User
    $Details = [System.Collections.Generic.List[string]]::new()
    $New = {
        param([string]$Code, [string]$Severity, [string]$Cause, [string]$Fix, $Link)
        [pscustomobject]@{ Code = $Code; Severity = $Severity; Cause = $Cause; Fix = $Fix; FixLink = $Link; Details = $Details.ToArray() }
    }
    $TenantQ = [uri]::EscapeDataString([string]$TenantFilter)
    $OneDriveLink = [pscustomobject]@{ Label = 'OneDrive (grant access to the OneDrive)'; Href = "/teams-share/onedrive?tenantFilter=$TenantQ" }
    $SiteLink = [pscustomobject]@{ Label = 'SharePoint (site members and permissions)'; Href = "/teams-share/sharepoint?tenantFilter=$TenantQ" }
    $TeamLink = if ($L.Team.Id) { [pscustomobject]@{ Label = "Edit team $($L.Team.DisplayName) (members)"; Href = "/identity/administration/groups/edit?groupId=$($L.Team.Id)&groupType=Microsoft%20365&tenantFilter=$TenantQ" } } else { $null }
    $SignInLink = if ($U.UserPrincipalName) { [pscustomobject]@{ Label = 'Sign-in Failure Explainer'; Href = "/identity/reports/signin-explainer?userPrincipalName=$([uri]::EscapeDataString($U.UserPrincipalName))&tenantFilter=$TenantQ" } } else { $null }
    $ChannelOpen = if ($L.Channel.WebUrl) { " Open the channel: $($L.Channel.WebUrl)" } else { '' }

    if ($Result.Mode -eq 'Search' -and -not $Result.Resolved) {
        $Count = @($Result.Candidates).Count
        if ($Count -gt 1) { return (& $New 'MultipleMatches' 'info' "$Count files match. Pick the one the user is trying to open." 'Resolve one of the candidates below.' $null) }
        if ($Count -eq 0 -and -not $ResolveError) {
            $Details.Add('Chat files are stored in the OneDrive of the person who SENT them, so search with the sender, not the person who cannot open the file.')
            $Details.Add('Private and shared channel files are in separate sites and are not searched; paste the file link instead.')
            return (& $New 'NotFound' 'warning' 'No file with that name was found in the user''s Teams chat files or their teams'' libraries.' 'Search again as the sender of the chat file, or paste the file link from Teams (... > Copy link).' $null)
        }
    }

    if (-not $Result.Resolved) {
        $Host_ = try { ([uri]$Result.ResolvedUrl).Host } catch { $null }
        if ($ResolveError -match '(?i)accessDenied|403|Forbidden|unauthori') {
            if ($Host_) { $Details.Add("The link points at $Host_.") }
            return (& $New 'OtherTenantOrNoAccess' 'warning' 'CIPP could not open the link. It most likely belongs to another organisation (a file shared from a partner''s tenant or a shared channel hosted elsewhere), so nothing in this tenant controls access.' 'Ask the sender''s organisation to share the file with the user again, or to allow B2B direct connect for shared channels.' $null)
        }
        if ($ResolveError -match '(?i)itemNotFound|404|not found|invalidRequest|400') {
            return (& $New 'NotFound' 'error' 'The link does not resolve to a file. The file was deleted or moved, the sharing link was removed or expired, or the link belongs to another organisation.' 'Check the site or OneDrive recycle bin, then ask the sender for a fresh link.' $SiteLink)
        }
        return (& $New 'Unresolved' 'warning' 'The file could not be resolved.' 'Paste the link from Teams (... > Copy link) or the browser address bar and try again.' $null)
    }

    $Where = switch ($L.Type) {
        'OneDrive' { if ($L.IsChatFile) { "This is a Teams chat file. It is stored in $($L.Owner.DisplayName)'s OneDrive, not in Teams and not in the other person's OneDrive." } else { "The file is in $($L.Owner.DisplayName)'s OneDrive." } }
        'TeamSite' { "The file is in the team site of $($L.Team.DisplayName)$(if ($L.Channel) { ", in the files of the standard channel $($L.Channel.DisplayName)" })." }
        'PrivateChannelSite' { "The file is in the separate site of the private channel $($L.Channel.DisplayName)$(if ($L.Team) { " in team $($L.Team.DisplayName)" }). Team members do NOT get access; only channel members do." }
        'SharedChannelSite' { "The file is in the separate site of the shared channel $($L.Channel.DisplayName)$(if ($L.Team) { " hosted by team $($L.Team.DisplayName)" }). Access comes from channel membership or from a team the channel is shared with." }
        default { "The file is in the SharePoint site $($L.SiteUrl)." }
    }
    $Details.Add($Where)

    if (-not $U) {
        return (& $New 'LocationOnly' 'info' $Where 'Add the affected user to see whether they are covered and what the smallest fix is.' $null)
    }
    if (-not $U.Found) {
        if ($UserLookupFailed) { return (& $New 'UserUnknown' 'warning' "Could not read $($U.Requested) from the directory." 'Retry, or check that CIPP can read users in this tenant.' $null) }
        if ($L.Type -eq 'SharedChannelSite') {
            return (& $New 'ExternalUser' 'warning' "$($U.Requested) is not a user in this tenant. In a shared channel an external person joins through B2B direct connect, not as a guest." 'Check the External tenants list below: B2B direct connect must be allowed inbound here and outbound in the user''s home tenant, then a channel owner adds them to the channel.' $null)
        }
        return (& $New 'ExternalUser' 'warning' "$($U.Requested) is not a user in this tenant, so they can only open the file through a link shared with their email address or an existing guest account." "Ask the file owner to share it with their email address (Share > specific people)." $(if ($L.Type -eq 'OneDrive') { $OneDriveLink } else { $SiteLink }))
    }
    if ($U.AccountEnabled -eq $false) {
        return (& $New 'UserDisabled' 'error' "$($U.UserPrincipalName) is disabled, so no permission will help." 'Enable the account if they should still have access.' $null)
    }

    if ($U.HasAccess -eq 'Yes') {
        $Details.Add("Access through: $(@($U.AccessVia) -join '; ').")
        return (& $New 'HasAccess' 'success' "$($U.UserPrincipalName) already has access to this file, so the problem is not membership or permissions." 'Check they are signed in to Teams / the browser with this account (not a personal or another organisation''s account), that Conditional Access or an unmanaged-device policy is not blocking SharePoint, and that the link they open is this file.' $SignInLink)
    }
    if ($U.HasAccess -eq 'Unknown') {
        return (& $New 'AccessUnknown' 'warning' "$Where CIPP could not read the file's permissions, so access could not be checked." 'See the errors below and retry.' $null)
    }

    switch ($L.Type) {
        'OneDrive' {
            if ($L.Owner.State -in @('Disabled', 'Deleted')) {
                return (& $New 'OwnerGone' 'error' "$Where The owner's account is $($L.Owner.State.ToLower()), so the file is only kept by OneDrive retention and the owner cannot share it." "Give a manager access to $($L.Owner.DisplayName)'s OneDrive and have them share or move the file before retention removes it." $OneDriveLink)
            }
            $People = @($Result.Permissions | Where-Object { $_.linkScope -eq 'users' })
            if ($L.IsChatFile) { $Details.Add('Teams shares a chat file only with the people in the chat when it was sent. Being added to the chat later, or being in the same team, does not give access.') }
            if ($People.Count -gt 0) { $Details.Add("People-specific link(s) cover: $(($People.principal -replace '^Specific people: ', '') -join '; ').") }
            return (& $New 'OneDriveNotShared' 'error' "$Where It was not shared with $($U.UserPrincipalName)." "Ask $($L.Owner.DisplayName) to share the file with $($U.UserPrincipalName) (Share > specific people). If they are unavailable, grant access to their OneDrive in CIPP and share it from there." $OneDriveLink)
        }
        'TeamSite' {
            if ($TeamLink -and $U.TeamMember -eq $false) {
                return (& $New 'NotTeamMember' 'error' "$Where $($U.UserPrincipalName) is not a member of the team." "Add $($U.UserPrincipalName) to the team $($L.Team.DisplayName) as a member. Access follows within a few minutes." $TeamLink)
            }
            return (& $New 'UniquePermissions' 'error' "$Where $($U.UserPrincipalName) is a team member but is not covered, so the file or a parent folder has its own (broken-inheritance) permissions. Team membership is not the problem." "Grant $($U.UserPrincipalName) access to the file or folder (or restore inheritance) in the site." $SiteLink)
        }
        'PrivateChannelSite' {
            if ($U.TeamMember -eq $false) {
                return (& $New 'NotTeamMember' 'error' "$Where $($U.UserPrincipalName) is not even in the parent team." "Add them to team $($L.Team.DisplayName) first, then a channel owner adds them to the private channel (Teams: channel > ... > Manage channel > Members).$ChannelOpen" $TeamLink)
            }
            if ($U.ChannelMember -eq $false) {
                return (& $New 'NotChannelMember' 'error' "$Where $($U.UserPrincipalName) is in the team but not in the private channel. This is the usual cause: team membership never grants private channel files." "A channel owner adds $($U.UserPrincipalName) to the channel (Teams: channel > ... > Manage channel > Members > Add).$ChannelOpen" $TeamLink)
            }
            return (& $New 'ChannelSiteUnsynced' 'error' "$Where $($U.UserPrincipalName) is a channel member but is not covered. The channel site's membership has not synced, or the file has its own permissions." 'Grant access on the channel site, or remove and re-add them to the channel to resync.' $SiteLink)
        }
        'SharedChannelSite' {
            $Ext = @($Result.Membership.ExternalTenants)
            if ($Ext.Count -gt 0) { $Details.Add("External members from $($Ext.Count) other tenant(s); see the External tenants list for their B2B direct connect setting.") }
            if ($U.ChannelMember -eq $false -and -not $U.SharedChannelViaTeam) {
                return (& $New 'NotChannelMember' 'error' "$Where $($U.UserPrincipalName) is not a member of the shared channel and is not in any team it is shared with." "A channel owner adds $($U.UserPrincipalName) to the shared channel, or shares the channel with a team they are in (Teams: channel > ... > Share channel).$ChannelOpen" $TeamLink)
            }
            return (& $New 'ChannelSiteUnsynced' 'error' "$Where $($U.UserPrincipalName) is covered by channel membership but not by the site. The site membership has not synced, or the file has its own permissions." 'Grant access on the channel site, or remove and re-add them to the channel to resync.' $SiteLink)
        }
        default {
            return (& $New 'NoSitePermission' 'error' "$Where $($U.UserPrincipalName) has no permission on it." "Add them to the site's Members group, or share the file with them." $SiteLink)
        }
    }
}
