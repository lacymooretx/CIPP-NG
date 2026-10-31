function Measure-CIPPOAuthGrantRisk {
    <#
    .SYNOPSIS
        Risk-scores the OAuth grants held by a tenant's client apps, from already-collected Graph data.
    .DESCRIPTION
        Pure rules, no Graph or table calls; Get-CIPPOAuthGrantRisk collects the inputs. Groups the tenant's
        application permissions (appRoleAssignedTo on Microsoft Graph, Exchange Online and SharePoint) and delegated
        grants (oauth2PermissionGrants) by client app, then scores each app:

          - a high-risk APPLICATION permission (app-only: every mailbox / file / directory object, no user signed in,
            "M365Pwned-style") is Critical;
          - a high-risk delegated scope consented for the whole tenant (AllPrincipals) is High;
          - a high-risk delegated scope consented by individual users is Medium, rising with the number of users;
          - an unverified publisher, an AI connector (Config/ShadowAI.json) or offline_access next to a high-risk
            scope raises the score; a disabled service principal halves it;
          - Microsoft first-party apps are Low and not scored.

        The high-risk list is the CIPP-11 list below plus every Critical entry of Config/RiskyPermissions.json; its High
        and Medium entries count as medium (promoting its High entries too made a third of a real tenant's apps Critical,
        e.g. Application.ReadWrite.OwnedBy or DeviceManagementConfiguration.ReadWrite.All). Apps registered in the
        consumer (personal Microsoft account) tenant are labelled as such: Graph reports their publisher as
        "Microsoft Accounts", which reads like Microsoft but is whoever registered the app (often an older ISV app). Each app gets plain-language reasons, a blast-radius sentence and a
        suggested action. Aspendora fork addition (Vikunja CIPP-11).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # Every service principal in the tenant (id, appId, displayName, appOwnerOrganizationId, publisherName,
        # verifiedPublisher, accountEnabled, createdDateTime).
        [object[]]$ServicePrincipals = @(),
        # The resource service principals whose appRoles resolve appRoleId to a permission name.
        [object[]]$ResourceServicePrincipals = @(),
        # appRoleAssignedTo rows of the resource service principals (appRoleId, principalId, principalType, resourceId).
        [object[]]$AppRoleAssignments = @(),
        # oauth2PermissionGrants (clientId, consentType, principalId, resourceId, scope).
        [object[]]$Grants = @(),
        # reports/servicePrincipalSignInActivities rows, or $null when they could not be read (no P1): unknown.
        [object[]]$SignInActivities = $null,
        # Config/ShadowAI.json entries (name, vendor, matchNames, appIds).
        [object[]]$AiCatalog = @(),
        # Config/RiskyPermissions.json entries (name, type, risk, reason).
        [object[]]$RiskyPermissions = @(),
        # The tenant's own id: apps registered in the tenant itself are not penalised for an unverified publisher.
        [string]$HomeTenantId,
        [datetime]$Now = (Get-Date).ToUniversalTime(),
        [int]$StaleDays = 90
    )

    $MicrosoftTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

    # CIPP-11 high-risk list: app-only phrase, delegated phrase ({who} = the users it can act for).
    $HighRisk = @{
        'Mail.Read'                          = @('read every mailbox in the tenant', 'read the mailbox of {who}')
        'Mail.ReadWrite'                     = @('read, change and delete mail in every mailbox in the tenant', 'read, change and delete the mail of {who}')
        'Mail.Send'                          = @('send mail as any user in the tenant', 'send mail as {who}')
        'MailboxSettings.ReadWrite'          = @('change rules, forwarding and settings of every mailbox', 'change mailbox rules and forwarding for {who}')
        'full_access_as_app'                 = @('read and change every mailbox in the tenant over EWS', 'read and change every mailbox over EWS')
        'EWS.AccessAsUser.All'               = @('read and change mailboxes over EWS', 'read and change, over EWS, every mailbox {who} can open')
        'Files.Read.All'                     = @('read every file in OneDrive and SharePoint', 'read every file {who} can reach in OneDrive and SharePoint')
        'Files.ReadWrite.All'                = @('read, change and delete every file in OneDrive and SharePoint', 'read, change and delete every file {who} can reach')
        'Sites.Read.All'                     = @('read every SharePoint site', 'read every SharePoint site {who} can reach')
        'Sites.ReadWrite.All'                = @('read and change every SharePoint site', 'read and change every SharePoint site {who} can reach')
        'Sites.FullControl.All'              = @('take full control of every SharePoint site', 'take full control of every SharePoint site {who} can reach')
        'Directory.ReadWrite.All'            = @('change any user, group or other directory object', 'change directory objects with the rights of {who}')
        'RoleManagement.ReadWrite.Directory' = @('assign any admin role, including Global Administrator', 'assign admin roles with the rights of {who}')
        'AppRoleAssignment.ReadWrite.All'    = @('grant itself or any app any permission', 'grant app permissions with the rights of {who}')
        'Application.ReadWrite.All'          = @('add credentials to any app and act as it', 'change apps and their credentials with the rights of {who}')
        'User.ReadWrite.All'                 = @('change any user account', 'change user accounts with the rights of {who}')
        'Directory.AccessAsUser.All'         = @('act on the directory as any user', 'do anything in the directory that {who} can do')
    }
    $ConsumerTenant = '9188040d-6c67-4c5b-b112-36a304b66dad'
    # RiskyPermissions.json: Critical becomes high-risk, High and Medium become medium. Keyed "Type|Name".
    $Catalog = @{}
    foreach ($P in @($RiskyPermissions)) {
        if (-not $P.name -or -not $P.type) { continue }
        $Catalog["$($P.type)|$($P.name)"] = $P
    }
    $DataScope = '^(Mail\.|MailboxSettings\.|full_access_as_app$|EWS\.|Files\.|Sites\.)'

    $Classify = {
        param([string]$Name, [string]$Type)
        if ($HighRisk.ContainsKey($Name)) { return 'High' }
        $Entry = $Catalog["$Type|$Name"]
        if ($Entry -and $Entry.risk -eq 'Critical') { return 'High' }
        if ($Entry -and $Entry.risk -in @('High', 'Medium')) { return 'Medium' }
        return 'Normal'
    }
    $Phrase = {
        param([string]$Name, [string]$Type, [string]$Who)
        if ($HighRisk.ContainsKey($Name)) {
            $Text = $HighRisk[$Name][$(if ($Type -eq 'Application') { 0 } else { 1 })]
        } elseif ($Type -eq 'Application') {
            $Text = "use $Name across the whole tenant"
        } else {
            $Text = "use $Name as {who}"
        }
        return $Text.Replace('{who}', $Who)
    }

    # AI catalog matcher: appIds first, then matchNames (word-bounded for short names, which otherwise hit
    # unrelated apps, e.g. 'gong' or 'coda').
    $AiMatch = {
        param($AppId, $Name)
        foreach ($Entry in @($AiCatalog)) {
            if ($AppId -and @($Entry.appIds) -contains $AppId) { return $Entry }
        }
        if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
        $Haystack = $Name.ToLowerInvariant()
        foreach ($Entry in @($AiCatalog)) {
            foreach ($M in @($Entry.matchNames)) {
                if (-not $M) { continue }
                $Needle = ([string]$M).ToLowerInvariant()
                if ($Needle.Length -ge 6) {
                    if ($Haystack.Contains($Needle)) { return $Entry }
                } elseif ($Haystack -match "(?<![a-z0-9])$([regex]::Escape($Needle))(?![a-z0-9])") {
                    return $Entry
                }
            }
        }
        return $null
    }

    $SpById = @{}
    foreach ($Sp in @($ServicePrincipals)) { if ($Sp.id) { $SpById[[string]$Sp.id] = $Sp } }
    $RoleNames = @{}
    $ResourceNames = @{}
    foreach ($R in @($ResourceServicePrincipals)) {
        $ResourceNames[[string]$R.id] = [string]$R.displayName
        foreach ($Role in @($R.appRoles)) { if ($Role.id) { $RoleNames["$($R.id)|$($Role.id)"] = [string]$Role.value } }
    }
    $SignIns = $null
    if ($null -ne $SignInActivities) {
        $SignIns = @{}
        foreach ($S in @($SignInActivities)) {
            if (-not $S.appId) { continue }
            # As a client: delegated or app-only sign-ins. lastSignInActivity also counts use as a resource.
            $Dates = @($S.delegatedClientSignInActivity.lastSignInDateTime, $S.applicationAuthenticationClientSignInActivity.lastSignInDateTime) | Where-Object { $_ }
            if (-not $Dates) { $Dates = @($S.lastSignInActivity.lastSignInDateTime | Where-Object { $_ }) }
            $Last = $Dates | ForEach-Object { try { ([datetimeoffset]$_).UtcDateTime } catch { $null } } | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
            $SignIns[[string]$S.appId] = $Last
        }
    }

    # --- Inventory, per client service principal ---
    $Apps = @{}
    $GetApp = {
        param([string]$SpId, [string]$FallbackName)
        if (-not $Apps.ContainsKey($SpId)) {
            $Apps[$SpId] = [pscustomobject]@{
                Sp          = $SpById[$SpId]
                SpId        = $SpId
                Name        = $FallbackName
                Permissions = [System.Collections.Generic.List[object]]::new()
                Users       = [System.Collections.Generic.HashSet[string]]::new()
                TenantWide  = $false
            }
        }
        return $Apps[$SpId]
    }

    foreach ($A in @($AppRoleAssignments)) {
        if ($A.principalType -and $A.principalType -ne 'ServicePrincipal') { continue }
        if (-not $A.principalId -or -not $A.appRoleId) { continue }
        $Name = $RoleNames["$($A.resourceId)|$($A.appRoleId)"]
        if (-not $Name) { $Name = [string]$A.appRoleId }
        $App = & $GetApp ([string]$A.principalId) ([string]$A.principalDisplayName)
        $App.Permissions.Add([pscustomobject]@{
                Resource   = $ResourceNames[[string]$A.resourceId] ?? [string]$A.resourceDisplayName
                Permission = $Name
                Type       = 'Application'
                Consent    = 'App-only'
                Users      = 0
                TenantWide = $true
            })
    }

    foreach ($ClientGroup in @(@($Grants) | Where-Object { $_.clientId } | Group-Object clientId)) {
        $App = & $GetApp ([string]$ClientGroup.Name) ''
        $ByScope = [ordered]@{}
        foreach ($G in $ClientGroup.Group) {
            $Resource = $ResourceNames[[string]$G.resourceId] ?? $SpById[[string]$G.resourceId].displayName ?? [string]$G.resourceId
            $IsAll = $G.consentType -eq 'AllPrincipals'
            if ($IsAll) { $App.TenantWide = $true } elseif ($G.principalId) { [void]$App.Users.Add([string]$G.principalId) }
            foreach ($Scope in @(([string]$G.scope) -split '\s+' | Where-Object { $_ })) {
                $Key = "$Resource|$Scope"
                if (-not $ByScope.Contains($Key)) {
                    $ByScope[$Key] = [pscustomobject]@{ Resource = $Resource; Permission = $Scope; TenantWide = $false; Users = [System.Collections.Generic.HashSet[string]]::new() }
                }
                if ($IsAll) { $ByScope[$Key].TenantWide = $true } elseif ($G.principalId) { [void]$ByScope[$Key].Users.Add([string]$G.principalId) }
            }
        }
        foreach ($S in $ByScope.Values) {
            $App.Permissions.Add([pscustomobject]@{
                    Resource   = $S.Resource
                    Permission = $S.Permission
                    Type       = 'Delegated'
                    Consent    = if ($S.TenantWide) { 'Tenant-wide' } else { "$($S.Users.Count) user$(if ($S.Users.Count -ne 1) { 's' })" }
                    Users      = $S.Users.Count
                    TenantWide = $S.TenantWide
                })
        }
    }

    # --- Scoring ---
    $Results = foreach ($App in $Apps.Values) {
        $Sp = $App.Sp
        $AppId = [string]$Sp.appId
        $DisplayName = if ($Sp.displayName) { [string]$Sp.displayName } elseif ($App.Name) { $App.Name } else { $App.SpId }
        $Verified = [string]$Sp.verifiedPublisher.displayName
        $IsMicrosoft = [string]$Sp.appOwnerOrganizationId -in $MicrosoftTenants
        $IsConsumer = [string]$Sp.appOwnerOrganizationId -eq $ConsumerTenant
        $Publisher = if ($IsMicrosoft) { 'Microsoft' } elseif ($IsConsumer -and -not $Verified) { 'Personal Microsoft account app' } elseif ($Verified) { $Verified } elseif ($Sp.publisherName) { [string]$Sp.publisherName } else { 'Unknown' }
        $Enabled = $Sp.accountEnabled -ne $false
        $Ai = if (-not $IsMicrosoft) { & $AiMatch $AppId $DisplayName } else { $null }

        foreach ($P in $App.Permissions) { $P | Add-Member -NotePropertyName Risk -NotePropertyValue (& $Classify $P.Permission $P.Type) -Force }
        $High = @($App.Permissions | Where-Object { $_.Risk -eq 'High' })
        $Medium = @($App.Permissions | Where-Object { $_.Risk -eq 'Medium' })
        $DataPerms = @($App.Permissions | Where-Object { $_.Permission -match $DataScope })
        $HasOffline = @($App.Permissions | Where-Object { $_.Type -eq 'Delegated' -and $_.Permission -eq 'offline_access' }).Count -gt 0

        $LastSignIn = $null
        $SignInKnown = $false
        if ($null -ne $SignIns -and $AppId) {
            $SignInKnown = $true
            $LastSignIn = $SignIns[$AppId]
        }

        $Reasons = [System.Collections.Generic.List[string]]::new()
        $Blast = [System.Collections.Generic.List[string]]::new()
        $Score = 0

        if ($IsMicrosoft) {
            $Reasons.Add('Microsoft first-party app: not scored.')
        } else {
            $Points = foreach ($P in $App.Permissions) {
                if ($P.Type -eq 'Application') {
                    if ($P.Risk -eq 'High') { 100 } elseif ($P.Risk -eq 'Medium') { 30 }
                } elseif ($P.TenantWide) {
                    if ($P.Risk -eq 'High') { 65 } elseif ($P.Risk -eq 'Medium') { 20 }
                } else {
                    if ($P.Risk -eq 'High') { 30 + [math]::Min(2 * $P.Users, 30) } elseif ($P.Risk -eq 'Medium') { 10 }
                }
            }
            $Score = [int](@($Points) + 0 | Measure-Object -Maximum).Maximum
            if ($High.Count -gt 1) { $Score += [math]::Min(5 * ($High.Count - 1), 20) }

            $AppOnlyHigh = @($High | Where-Object { $_.Type -eq 'Application' })
            $DelegatedHigh = @($High | Where-Object { $_.Type -eq 'Delegated' })
            if ($AppOnlyHigh) {
                $Reasons.Add("App-only (application) permission$(if ($AppOnlyHigh.Count -gt 1) { 's' }) $((@($AppOnlyHigh.Permission) | Sort-Object -Unique) -join ', '): tenant-wide access with no user signed in, so no sign-in, MFA or Conditional Access stands in the way.")
                foreach ($P in $AppOnlyHigh) { $Blast.Add((& $Phrase $P.Permission 'Application' '')) }
            }
            foreach ($Wide in @($true, $false)) {
                $Set = @($DelegatedHigh | Where-Object { $_.TenantWide -eq $Wide })
                if (-not $Set) { continue }
                if ($Wide) {
                    $Reasons.Add("Delegated $((@($Set.Permission) | Sort-Object -Unique) -join ', ') consented for the whole tenant (admin consent): it can act for any user who signs in to it.")
                    $Who = 'any user who signs in to it'
                } else {
                    $Max = [int](@($Set.Users) + 0 | Measure-Object -Maximum).Maximum
                    $Reasons.Add("Delegated $((@($Set.Permission) | Sort-Object -Unique) -join ', ') consented by $Max user$(if ($Max -ne 1) { 's' }).")
                    $Who = "the $Max user$(if ($Max -ne 1) { 's' }) who consented"
                }
                foreach ($P in $Set) { $Blast.Add((& $Phrase $P.Permission 'Delegated' $Who)) }
            }
            if (-not $High -and $Medium) {
                $Reasons.Add("Medium-risk permissions: $((@($Medium.Permission) | Sort-Object -Unique) -join ', ').")
            }
            if ($HasOffline -and $DelegatedHigh) {
                $Score += 10
                $Reasons.Add('offline_access with high-risk scopes: refresh tokens keep that access working without the user present.')
            }
            $IsHome = $HomeTenantId -and [string]$Sp.appOwnerOrganizationId -eq $HomeTenantId
            if ($High -and $IsHome) {
                $Reasons.Add('Registered in this tenant (single-tenant app or script).')
            } elseif ($High -and -not $Verified) {
                $Score += 20
                if ($IsConsumer) {
                    $Reasons.Add('Registered as a personal Microsoft account app (the consumer tenant). Graph shows its publisher as "Microsoft Accounts", but that is not Microsoft, and the real publisher is not verified. Older ISV apps (Zapier, QuickBooks) are registered this way too.')
                } else {
                    $Reasons.Add("Publisher is not verified (publisherName '$($Sp.publisherName ?? 'unknown')').")
                }
            }
            if ($Ai -and $DataPerms) {
                $Score += 15
                $Reasons.Add("AI connector ($($Ai.name), $($Ai.vendor)) with access to mail, files or sites: company data can leave for an AI service.")
            } elseif ($Ai) {
                $Reasons.Add("AI tool ($($Ai.name), $($Ai.vendor)).")
            }
            if ($High -and $SignInKnown) {
                if (-not $LastSignIn) {
                    $Score += 5
                    $Reasons.Add('No recorded sign-in: the grant may be unused and can probably be removed.')
                } elseif ($LastSignIn -lt $Now.AddDays(-$StaleDays)) {
                    $Score += 5
                    $Reasons.Add("Not used since $($LastSignIn.ToString('yyyy-MM-dd')): the grant may no longer be needed.")
                }
            }
            if (-not $Enabled -and $Score -gt 0) {
                $Score = [int][math]::Floor($Score / 2)
                $Reasons.Add('Service principal is disabled: the grants are inert until it is re-enabled.')
            }
        }

        $Risk = if ($Score -ge 100) { 'Critical' } elseif ($Score -ge 60) { 'High' } elseif ($Score -ge 25) { 'Medium' } else { 'Low' }
        $BlastRadius = if ($Blast.Count) {
            "Can $((@($Blast) | Select-Object -Unique) -join '; ')$(if (@($High | Where-Object Type -EQ 'Application')) { ', without a user signed in' })."
        } else { '' }
        $Action = if ($IsMicrosoft -or $Risk -in @('Low')) {
            ''
        } elseif (-not $Enabled) {
            'Already disabled. If it is no longer needed, delete the service principal or remove its grants.'
        } else {
            $Steps = [System.Collections.Generic.List[string]]::new()
            $Steps.Add('Confirm with the client who uses this app and why.')
            $Steps.Add('If it is unknown or no longer needed, disable the service principal (accountEnabled=false): it stops working at once but keeps its config and grants, so it can be re-enabled.')
            if (@($High | Where-Object Type -EQ 'Application')) { $Steps.Add('Then remove the application permission (delete the appRoleAssignment), or delete the service principal.') }
            if (@($High | Where-Object { $_.Type -eq 'Delegated' -and $_.TenantWide })) { $Steps.Add('Remove the tenant-wide delegated grant (delete the AllPrincipals oauth2PermissionGrant).') }
            if (@($High | Where-Object { $_.Type -eq 'Delegated' -and -not $_.TenantWide })) { $Steps.Add('Remove the users'' delegated grants (Principal oauth2PermissionGrants) and revoke their sessions if the app is suspicious.') }
            $Steps.Add('If it is a legitimate vendor, add its appId to the OAuthHighRiskGrant alert allow-list.')
            $Steps -join ' '
        }

        [pscustomobject]@{
            DisplayName            = $DisplayName
            AppId                  = $AppId
            ServicePrincipalId     = $App.SpId
            Publisher              = $Publisher
            PublisherVerified      = [bool]$Verified
            AppOwnerOrganizationId = [string]$Sp.appOwnerOrganizationId
            IsMicrosoft            = $IsMicrosoft
            AccountEnabled         = $Enabled
            CreatedDateTime        = $Sp.createdDateTime
            ApplicationPermissions = @($App.Permissions | Where-Object Type -EQ 'Application' | ForEach-Object { "$($_.Resource): $($_.Permission)" } | Sort-Object -Unique)
            DelegatedPermissions   = @($App.Permissions | Where-Object Type -EQ 'Delegated' | ForEach-Object { "$($_.Resource): $($_.Permission) ($($_.Consent))" } | Sort-Object -Unique)
            HighRiskPermissions    = @($High | ForEach-Object { $_.Permission } | Sort-Object -Unique)
            DataPermissions        = @($DataPerms | ForEach-Object { $_.Permission } | Sort-Object -Unique)
            TenantWideConsent      = $App.TenantWide
            DelegatedUserCount     = $App.Users.Count
            ConsentScope           = (@(
                    if (@($App.Permissions | Where-Object Type -EQ 'Application')) { 'App-only' }
                    if ($App.TenantWide) { 'Tenant-wide delegated' }
                    if ($App.Users.Count) { "$($App.Users.Count) user$(if ($App.Users.Count -ne 1) { 's' })" }
                ) -join ', ')
            LastSignIn             = $LastSignIn
            SignInKnown            = $SignInKnown
            IsAiConnector          = [bool]$Ai
            AiTool                 = if ($Ai) { [string]$Ai.name } else { $null }
            AiVendor               = if ($Ai) { [string]$Ai.vendor } else { $null }
            Score                  = $Score
            Risk                   = $Risk
            Reasons                = @($Reasons)
            BlastRadius            = $BlastRadius
            SuggestedAction        = $Action
            Permissions            = @($App.Permissions | Select-Object Resource, Permission, Type, Consent, Users, Risk)
        }
    }

    return @($Results | Sort-Object -Property @{ Expression = 'Score'; Descending = $true }, @{ Expression = 'DisplayName'; Descending = $false })
}
