function Get-CIPPGuestReviewReportData {
    <#
    .SYNOPSIS
        Gather the Guest Access Review report model for a single tenant.
    .DESCRIPTION
        Client-facing guest review built on Get-CIPPGuestInventory: a cleanup proposal (REMOVE / DISABLE / REVIEW, each
        with its reason), the guests being kept, and the tenant settings that decide how guests get in (SharePoint and
        OneDrive Entra B2B integration, SharePoint sharing level, who may invite, guest user role). Read only: the report
        proposes, a person approves, and removal is done from the Guest Inventory page. Aspendora fork addition
        (Vikunja CIPP-14).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Sections = [System.Collections.Generic.List[object]]::new()
    function Add-Finding($Title, $Status, $Detail) { $Findings.Add(@{ Title = $Title; Status = $Status; Detail = $Detail }) }
    function Add-Section($Title, $Status, $Description, $Columns, $Rows, $Empty) {
        $Sections.Add(@{ Title = $Title; Status = $Status; Description = $Description; Columns = $Columns; Rows = $Rows; Empty = $Empty })
    }
    function New-RowList { , [System.Collections.Generic.List[object]]::new() }
    function Format-Days($Days, $Never) { if ($null -ne $Days) { "$Days d ago" } else { $Never } }

    $Org = $null
    try { $Org = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/organization' -tenantid $TenantFilter | Select-Object -First 1 } catch {}
    $TenantName = if ($Org.displayName) { $Org.displayName } else { $TenantFilter }
    $DefaultDomain = ($Org.verifiedDomains | Where-Object { $_.isDefault }).name
    if (-not $DefaultDomain) { $DefaultDomain = $TenantFilter }

    $Inventory = $null
    try {
        $Inventory = Get-CIPPGuestInventory -TenantFilter $TenantFilter
    } catch {
        $r = New-RowList; $r.Add(@("$($_.Exception.Message)"))
        Add-Section 'Guest Accounts' 'warn' 'The guest list could not be retrieved.' @('Error') $r 'Data unavailable.'
        return @{ Title = 'Guest Access Review'; TenantName = $TenantName; TenantDomain = $DefaultDomain; GeneratedDate = (Get-Date).ToString('dd MMMM yyyy'); Findings = $Findings; Sections = $Sections }
    }
    $Guests = @($Inventory.Guests)
    $S = $Inventory.Summary
    $SignIn = [bool]$Inventory.TenantContext.SignInActivityAvailable

    # Cleanup proposal, ordered by action then name. Index loops, not pipelines: each row is an array and piping a
    # list of arrays unrolls a single row into its cells.
    $Proposal = New-RowList
    foreach ($Action in @('REMOVE', 'DISABLE', 'REVIEW')) {
        $Bucket = @($Guests | Where-Object { $_.recommendedAction -eq $Action } | Sort-Object -Property displayName)
        for ($i = 0; $i -lt $Bucket.Count; $i++) {
            $G = $Bucket[$i]
            $Access = @($G.teams, $G.groups | Where-Object { $_ }) -join '; '
            $Proposal.Add(@(
                    $Action,
                    [string]$G.displayName,
                    [string]($G.mail ?? $G.userPrincipalName),
                    [string]$G.accountType,
                    $(if ($G.invitedBy) { "$($G.invitedBy)$(if ($G.inviterState -eq 'Disabled') { ' (disabled)' })" } else { 'Not recorded' }),
                    $(if ($SignIn) { Format-Days $G.daysSinceSignIn 'Never' } else { 'Not available' }),
                    $(if ($Access) { $Access } else { 'None' }),
                    [string]$G.reasons
                ))
        }
    }
    $ProposalStatus = if ($S.Remove -gt 0 -or $S.Disable -gt 0) { 'warn' } else { 'pass' }
    Add-Section 'Proposed Guest Cleanup' $ProposalStatus "Recommended actions for approval. Nothing has been changed. REMOVE: invitation unredeemed for $($Inventory.PendingDays)+ days, or already disabled and unused. DISABLE: no sign-in for $($Inventory.StaleDays)+ days. REVIEW: personal account, inviter has left, or activity unknown." @('Action', 'Guest', 'Email', 'Account type', 'Invited by', 'Last sign-in', 'Teams / groups', 'Reason') $Proposal 'No guest needs action.'

    $Kept = New-RowList
    $KeepRows = @($Guests | Where-Object { $_.recommendedAction -eq 'KEEP' } | Sort-Object -Property displayName)
    for ($i = 0; $i -lt $KeepRows.Count; $i++) {
        $G = $KeepRows[$i]
        $Kept.Add(@([string]$G.displayName, [string]($G.mail ?? $G.userPrincipalName), [string]$G.accountType, $(if ($G.invitedBy) { [string]$G.invitedBy } else { 'Not recorded' }), $(if ($SignIn) { Format-Days $G.daysSinceSignIn 'Never' } else { 'Not available' }), $(if ($G.teams) { [string]$G.teams } else { '' })))
    }
    Add-Section 'Active Guests (no action)' 'pass' 'Guests that redeemed their invitation and signed in recently.' @('Guest', 'Email', 'Account type', 'Invited by', 'Last sign-in', 'Teams') $Kept 'No active guests.'

    $C = $Inventory.TenantContext
    $Settings = New-RowList
    $B2B = if ($null -eq $C.SharePointB2BIntegration) { 'Unknown' } elseif ($C.SharePointB2BIntegration) { 'On: people shared with from SharePoint/OneDrive become Entra guests (recommended, CIS 7.2.2)' } else { 'Off: SharePoint/OneDrive external users are not Entra guests and Conditional Access does not apply to them' }
    $Settings.Add(@('SharePoint / OneDrive Entra B2B integration', $B2B))
    $Settings.Add(@('SharePoint external sharing level', $(if ($C.SharePointSharingCapability) { [string]$C.SharePointSharingCapability } else { 'Unknown' })))
    $Settings.Add(@('Who can invite guests', $(if ($C.AllowInvitesFrom) { [string]$C.AllowInvitesFrom } else { 'Unknown' })))
    $Settings.Add(@('Guest directory permissions', $(if ($C.GuestUserRole) { [string]$C.GuestUserRole } else { 'Unknown' })))
    $Settings.Add(@('Guest sign-in activity', $(if ($SignIn) { 'Available' } else { 'Not available: requires Entra ID P1' })))
    $InviteStatus = if ($C.AllowInvitesFrom -eq 'everyone') { 'warn' } else { 'pass' }
    Add-Section 'Guest Access Settings' $InviteStatus 'Tenant settings that decide how guests are created and what they can see.' @('Setting', 'Value') $Settings $null

    $Summary = New-RowList
    foreach ($Pair in @(@('Guests', $S.Total), @('Remove', $S.Remove), @('Disable', $S.Disable), @('Review', $S.Review), @('Keep', $S.Keep), @('Invitations not yet redeemed', $S.Pending), @('Personal accounts', $S.Personal), @('Inviter disabled', $S.InviterGone), @('Guests in Teams', $S.InTeams))) {
        $Summary.Add(@([string]$Pair[0], [string]$Pair[1]))
    }
    Add-Section 'Summary' 'pass' 'Guest counts by recommended action.' @('Measure', 'Count') $Summary $null

    if ($S.Total -eq 0) { Add-Finding 'No guest accounts' 'pass' 'The tenant has no guest users.' }
    if ($S.Remove -gt 0) { Add-Finding 'Guests to remove' 'warn' "$($S.Remove) guest(s) never redeemed their invitation or are disabled and unused." }
    if ($S.Disable -gt 0) { Add-Finding 'Inactive guests' 'warn' "$($S.Disable) guest(s) have not signed in for $($Inventory.StaleDays) days or more." }
    if ($S.Personal -gt 0) { Add-Finding 'Personal accounts' 'warn' "$($S.Personal) guest(s) use a personal email or Microsoft account rather than a business identity." }
    if ($S.InviterGone -gt 0) { Add-Finding 'Guests whose sponsor has left' 'warn' "$($S.InviterGone) guest(s) were invited by a user whose account is now disabled." }
    if ($C.AllowInvitesFrom -eq 'everyone') { Add-Finding 'Anyone can invite guests' 'warn' 'Guest invitations are allowed from everyone, including other guests.' }
    if ($S.Total -gt 0 -and $S.Remove -eq 0 -and $S.Disable -eq 0 -and $S.Review -eq 0) { Add-Finding 'Guest accounts are clean' 'pass' 'Every guest redeemed its invitation and signed in recently.' }
    foreach ($E in @($Inventory.Errors)) { Add-Finding 'Partial data' 'warn' $E }

    return @{
        Title         = 'Guest Access Review'
        TenantName    = $TenantName
        TenantDomain  = $DefaultDomain
        GeneratedDate = (Get-Date).ToString('dd MMMM yyyy')
        Findings      = $Findings
        Sections      = $Sections
    }
}
