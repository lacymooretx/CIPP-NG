# Pester tests for Get-CIPPGuestInventory and Get-CIPPGuestReviewReportData (Vikunja CIPP-14).
# Pins the recommended-action rules (REMOVE > DISABLE > REVIEW > KEEP), account-type detection from the identity
# issuer, consumer domains, inviter state, Team vs group memberships, the no-P1 fallback, partial failures, and that
# the report sorts rows without unrolling them.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Modules = Join-Path $RepoRoot 'Modules'
    foreach ($Name in 'Get-CIPPGuestInventory.ps1', 'Get-CIPPGuestReviewReportData.ps1') {
        $Path = Get-ChildItem -Path $Modules -Recurse -Filter $Name -File | Select-Object -First 1 -ExpandProperty FullName
        if (-not $Path) { throw "Could not locate $Name" }
        . $Path
    }

    function Test-CIPPStandardLicense { [CmdletBinding()] param($StandardName, $TenantFilter, $Preset, [switch]$SkipLog) }
    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, [switch]$ComplexFilter, $AsApp) }
    function New-GraphBulkRequest { [CmdletBinding()] param($Requests, $tenantid, $asapp) }
    function Get-CIPPSPOTenant { [CmdletBinding()] param($TenantFilter) }
    function Get-CippException { [CmdletBinding()] param($Exception) @{ NormalizedError = "$Exception" } }

    $script:Now = (Get-Date).ToUniversalTime()
    function script:Ago([int]$Days) { $script:Now.AddDays(-$Days).ToString('o') }

    # Guests go through JSON so they have the shape Graph returns.
    function script:New-Guest {
        param([string]$Id, [string]$Mail, [string]$State = 'Accepted', [bool]$Enabled = $true, [int]$CreatedDaysAgo = 400,
            [Nullable[int]]$SignInDaysAgo, [Nullable[int]]$StateChangeDaysAgo, [string]$Issuer = 'ExternalAzureAD')
        $G = [ordered]@{
            id = $Id; displayName = "Guest $Id"; mail = $Mail; userPrincipalName = "$($Mail -replace '@','_')#EXT#@contoso.onmicrosoft.com"
            createdDateTime = (Ago $CreatedDaysAgo); creationType = 'Invitation'; accountEnabled = $Enabled
            externalUserState = $State
            externalUserStateChangeDateTime = if ($null -ne $StateChangeDaysAgo) { Ago $StateChangeDaysAgo } else { Ago $CreatedDaysAgo }
            identities = @(@{ signInType = 'userPrincipalName'; issuer = 'contoso.onmicrosoft.com' })
        }
        if ($Issuer) { $G.identities += @{ signInType = 'federated'; issuer = $Issuer } }
        if ($null -ne $SignInDaysAgo) { $G.signInActivity = @{ lastSignInDateTime = (Ago $SignInDaysAgo); lastNonInteractiveSignInDateTime = $null; lastSuccessfulSignInDateTime = $null } }
        $G | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    }

    function script:Set-Fixture {
        param($Guests, [bool]$P1 = $true, $Inviters = @{}, $Groups = @{}, [switch]$BulkFails, $Spo = @{ EnableAzureADB2BIntegration = $true; SharingCapability = 'ExternalUserSharingOnly' }, $AllowInvites = 'adminsAndGuestInviters')
        $script:F = @{ Guests = @($Guests); P1 = $P1; Inviters = $Inviters; Groups = $Groups; BulkFails = [bool]$BulkFails; Spo = $Spo; AllowInvites = $AllowInvites }
    }
}

Describe 'Get-CIPPGuestInventory' {
    BeforeEach {
        Mock Test-CIPPStandardLicense { $script:F.P1 }
        Mock New-GraphGetRequest {
            if ($uri -like '*/users?*') { $script:LastUserUri = $uri; return $script:F.Guests }
            if ($uri -like '*authorizationPolicy*') { return [pscustomobject]@{ allowInvitesFrom = $script:F.AllowInvites; guestUserRoleId = '10dae51f-b6af-4016-8d66-8c2a99b929b3' } }
            if ($uri -like '*/organization') { return [pscustomobject]@{ displayName = 'Contoso'; verifiedDomains = @(@{ name = 'contoso.com'; isDefault = $true }) } }
            throw "unexpected GET $uri"
        }
        Mock New-GraphBulkRequest {
            if ($script:F.BulkFails) { throw 'batch failed' }
            foreach ($R in $Requests) {
                $Gid = $R.id.Substring(4)
                if ($R.id -like 'inv-*') {
                    $Body = if ($script:F.Inviters.ContainsKey($Gid)) { @{ value = @($script:F.Inviters[$Gid]) } } else { @{ value = @() } }
                } else {
                    $Body = @{ value = @($script:F.Groups[$Gid]) }
                }
                [pscustomobject]@{ id = $R.id; status = 200; body = ([pscustomobject]$Body | ConvertTo-Json -Depth 6 | ConvertFrom-Json) }
            }
        }
        Mock Get-CIPPSPOTenant { [pscustomobject]$script:F.Spo }
    }

    It 'recommends REMOVE for an invitation unredeemed past the pending threshold, measured from the latest invitation' {
        Set-Fixture @(
            (New-Guest -Id 'old' -Mail 'a@partner.com' -State 'PendingAcceptance' -CreatedDaysAgo 200 -StateChangeDaysAgo 45 -Issuer $null),
            (New-Guest -Id 'reinvited' -Mail 'b@partner.com' -State 'PendingAcceptance' -CreatedDaysAgo 200 -StateChangeDaysAgo 5 -Issuer $null)
        )
        $R = Get-CIPPGuestInventory -TenantFilter 'contoso.com'
        ($R.Guests | Where-Object id -EQ 'old').recommendedAction | Should -Be 'REMOVE'
        ($R.Guests | Where-Object id -EQ 'old').reasons | Should -BeLike '*not redeemed for 45 days*'
        ($R.Guests | Where-Object id -EQ 'old').accountType | Should -Be 'Not redeemed yet'
        ($R.Guests | Where-Object id -EQ 'reinvited').recommendedAction | Should -Be 'KEEP'
    }

    It 'recommends DISABLE for a redeemed guest with no sign-in past the stale threshold, and KEEP for a recent one' {
        Set-Fixture @(
            (New-Guest -Id 'stale' -Mail 's@partner.com' -SignInDaysAgo 120),
            (New-Guest -Id 'fresh' -Mail 'f@partner.com' -SignInDaysAgo 3),
            (New-Guest -Id 'never' -Mail 'n@partner.com' -CreatedDaysAgo 200)
        )
        $R = Get-CIPPGuestInventory -TenantFilter 'contoso.com'
        ($R.Guests | Where-Object id -EQ 'stale').recommendedAction | Should -Be 'DISABLE'
        ($R.Guests | Where-Object id -EQ 'fresh').recommendedAction | Should -Be 'KEEP'
        ($R.Guests | Where-Object id -EQ 'never').recommendedAction | Should -Be 'DISABLE'
        ($R.Guests | Where-Object id -EQ 'never').reasons | Should -BeLike '*never signed in*'
        $LastUserUri | Should -BeLike '*signInActivity*'
    }

    It 'recommends REMOVE for a guest that is already disabled and unused' {
        Set-Fixture @(New-Guest -Id 'dis' -Mail 'd@partner.com' -Enabled $false -SignInDaysAgo 300)
        (Get-CIPPGuestInventory -TenantFilter 'contoso.com').Guests[0].recommendedAction | Should -Be 'REMOVE'
    }

    It 'flags personal Microsoft accounts and consumer domains for REVIEW without overriding a stronger action' {
        Set-Fixture @(
            (New-Guest -Id 'msa' -Mail 'x@contractor.io' -SignInDaysAgo 2 -Issuer 'MicrosoftAccount'),
            (New-Guest -Id 'gmail' -Mail 'Someone@Gmail.com' -SignInDaysAgo 2 -Issuer 'mail'),
            (New-Guest -Id 'gmailstale' -Mail 'z@gmail.com' -SignInDaysAgo 200 -Issuer 'mail')
        )
        $R = Get-CIPPGuestInventory -TenantFilter 'contoso.com'
        $Msa = $R.Guests | Where-Object id -EQ 'msa'
        $Msa.accountType | Should -Be 'Personal Microsoft account'
        $Msa.recommendedAction | Should -Be 'REVIEW'
        $Gmail = $R.Guests | Where-Object id -EQ 'gmail'
        $Gmail.accountType | Should -Be 'Email one-time passcode'
        $Gmail.reasons | Should -BeLike '*consumer domain gmail.com*'
        ($R.Guests | Where-Object id -EQ 'gmailstale').recommendedAction | Should -Be 'DISABLE'
        ($R.Guests | Where-Object id -EQ 'gmailstale').reasons | Should -BeLike '*Personal account*'
        $R.Summary.Personal | Should -Be 3
    }

    It 'reports the inviter, flags a disabled inviter, and separates Teams from groups' {
        Set-Fixture @(New-Guest -Id 'g1' -Mail 'g1@partner.com' -SignInDaysAgo 2) -Inviters @{
            g1 = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Ken Miller'; userPrincipalName = 'ken@contoso.com'; accountEnabled = $false }
        } -Groups @{
            g1 = @(
                @{ '@odata.type' = '#microsoft.graph.group'; displayName = 'Project X'; resourceProvisioningOptions = @('Team') },
                @{ '@odata.type' = '#microsoft.graph.group'; displayName = 'Vendors'; resourceProvisioningOptions = @() },
                @{ '@odata.type' = '#microsoft.graph.directoryRole'; displayName = 'Guest Inviter' }
            )
        }
        $G = (Get-CIPPGuestInventory -TenantFilter 'contoso.com').Guests[0]
        $G.invitedBy | Should -Be 'Ken Miller'
        $G.inviterState | Should -Be 'Disabled'
        $G.recommendedAction | Should -Be 'REVIEW'
        $G.teams | Should -Be 'Project X'
        $G.groups | Should -Be 'Vendors'
        $G.groupCount | Should -Be 2
    }

    It 'without Entra ID P1 never selects signInActivity, never recommends DISABLE, and says activity is unknown' {
        Set-Fixture @(New-Guest -Id 'np' -Mail 'np@partner.com' -CreatedDaysAgo 400) -P1 $false
        $R = Get-CIPPGuestInventory -TenantFilter 'contoso.com'
        $LastUserUri | Should -Not -BeLike '*signInActivity*'
        $R.Guests[0].recommendedAction | Should -Be 'REVIEW'
        $R.Guests[0].reasons | Should -BeLike '*no Entra ID P1*'
        $R.TenantContext.SignInActivityAvailable | Should -BeFalse
    }

    It 'keeps going when the inviter/membership batch fails, leaving those fields unknown' {
        Set-Fixture @(New-Guest -Id 'g' -Mail 'g@partner.com' -SignInDaysAgo 1) -BulkFails
        $R = Get-CIPPGuestInventory -TenantFilter 'contoso.com'
        $R.Guests[0].inviterState | Should -Be 'Unknown'
        $R.Guests[0].groupCount | Should -BeNullOrEmpty
        $R.Guests[0].recommendedAction | Should -Be 'KEEP'
        @($R.Errors).Count | Should -Be 1
    }

    It 'returns tenant context and an empty inventory for a tenant with no guests' {
        Set-Fixture @()
        $R = Get-CIPPGuestInventory -TenantFilter 'contoso.com'
        $R.Summary.Total | Should -Be 0
        @($R.Guests).Count | Should -Be 0
        $R.TenantContext.SharePointB2BIntegration | Should -BeTrue
        $R.TenantContext.AllowInvitesFrom | Should -Be 'adminsAndGuestInviters'
        $R.TenantContext.GuestUserRole | Should -Be 'Limited (default)'
        Should -Invoke New-GraphBulkRequest -Times 0
    }
}

Describe 'Get-CIPPGuestReviewReportData' {
    BeforeEach {
        Mock Test-CIPPStandardLicense { $true }
        Mock New-GraphGetRequest {
            if ($uri -like '*/users?*') { return $script:F.Guests }
            if ($uri -like '*authorizationPolicy*') { return [pscustomobject]@{ allowInvitesFrom = $script:F.AllowInvites } }
            if ($uri -like '*/organization') { return [pscustomobject]@{ displayName = 'Contoso'; verifiedDomains = @(@{ name = 'contoso.com'; isDefault = $true }) } }
        }
        Mock New-GraphBulkRequest { foreach ($R in $Requests) { [pscustomobject]@{ id = $R.id; status = 200; body = [pscustomobject]@{ value = @() } } } }
        Mock Get-CIPPSPOTenant { [pscustomobject]@{ EnableAzureADB2BIntegration = $false; SharingCapability = 'ExternalUserAndGuestSharing' } }
    }

    It 'orders the cleanup proposal REMOVE, DISABLE, REVIEW with whole rows, and lists kept guests separately' {
        Set-Fixture @(
            (New-Guest -Id 'r' -Mail 'r@partner.com' -SignInDaysAgo 2 -Issuer 'MicrosoftAccount'),
            (New-Guest -Id 'd' -Mail 'd@partner.com' -SignInDaysAgo 150),
            (New-Guest -Id 'x' -Mail 'x@partner.com' -State 'PendingAcceptance' -CreatedDaysAgo 90 -Issuer $null),
            (New-Guest -Id 'k' -Mail 'k@partner.com' -SignInDaysAgo 1)
        ) -AllowInvites 'everyone'
        $M = Get-CIPPGuestReviewReportData -TenantFilter 'contoso.com'
        $M.Title | Should -Be 'Guest Access Review'
        $Proposal = $M.Sections | Where-Object { $_.Title -eq 'Proposed Guest Cleanup' }
        $Proposal.Rows.Count | Should -Be 3
        @($Proposal.Rows | ForEach-Object { , $_ } | ForEach-Object { $_[0] }) | Should -Be @('REMOVE', 'DISABLE', 'REVIEW')
        $Proposal.Rows[0].Count | Should -Be $Proposal.Columns.Count
        ($M.Sections | Where-Object { $_.Title -eq 'Active Guests (no action)' }).Rows.Count | Should -Be 1
        $Settings = ($M.Sections | Where-Object { $_.Title -eq 'Guest Access Settings' })
        $Settings.Status | Should -Be 'warn'
        $Settings.Rows[0][1] | Should -BeLike 'Off:*'
        @($M.Findings.Title) | Should -Contain 'Anyone can invite guests'
        @($M.Findings.Title) | Should -Contain 'Guests to remove'
    }

    It 'reports a clean tenant as clean' {
        Set-Fixture @(New-Guest -Id 'k' -Mail 'k@partner.com' -SignInDaysAgo 1)
        $M = Get-CIPPGuestReviewReportData -TenantFilter 'contoso.com'
        @($M.Findings.Title) | Should -Contain 'Guest accounts are clean'
        ($M.Sections | Where-Object { $_.Title -eq 'Proposed Guest Cleanup' }).Status | Should -Be 'pass'
    }
}
