# Aspendora fork (Vikunja CIPP-11): OAuth grant risk scoring rules (pure, Graph-shaped fixtures).
BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/OAuthRisk/Measure-CIPPOAuthGrantRisk.ps1')
    $script:Risky = @(Get-Content -Raw (Join-Path $RepoRoot 'Config/RiskyPermissions.json') | ConvertFrom-Json)
    $script:Ai = @(Get-Content -Raw (Join-Path $RepoRoot 'Config/ShadowAI.json') | ConvertFrom-Json)

    $script:Exo = [pscustomobject]@{ id = 'exo'; appId = '00000002-0000-0ff1-ce00-000000000000'; displayName = 'Office 365 Exchange Online'; appRoles = @([pscustomobject]@{ id = 'dc890d15-9560-4a4c-9b7f-a736ec74ec40'; value = 'full_access_as_app' }) }
    $script:Graph = [pscustomobject]@{ id = 'graph'; appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph'; appRoles = @(
            [pscustomobject]@{ id = '810c84a8-4a9e-49e6-bf7d-12d183f40d01'; value = 'Mail.Read' }
            [pscustomobject]@{ id = 'df021288-bdef-4463-88db-98f22de89214'; value = 'User.Read.All' }
            [pscustomobject]@{ id = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'; value = 'RoleManagement.ReadWrite.Directory' }
        )
    }
    function script:New-Sp {
        param($Id, $Name, $Owner = 'vendor-tenant', $Verified = 'Contoso Ltd', $Enabled = $true, $PublisherName = 'Contoso')
        [pscustomobject]@{ id = $Id; appId = "app-$Id"; displayName = $Name; appOwnerOrganizationId = $Owner; publisherName = $PublisherName; verifiedPublisher = [pscustomobject]@{ displayName = $Verified }; accountEnabled = $Enabled; createdDateTime = '2026-01-01T00:00:00Z' }
    }
    function script:Invoke-RiskMeasure {
        param($Sps, $Assignments = @(), $Grants = @(), $SignIns = $null, $HomeTenantId = 'home')
        Measure-CIPPOAuthGrantRisk -ServicePrincipals $Sps -ResourceServicePrincipals @($script:Exo, $script:Graph) -AppRoleAssignments $Assignments -Grants $Grants -SignInActivities $SignIns -AiCatalog $script:Ai -RiskyPermissions $script:Risky -HomeTenantId $HomeTenantId -Now ([datetime]'2026-10-31T00:00:00Z')
    }
    function script:New-Assignment { param($Sp, $Resource, $RoleId) [pscustomobject]@{ principalId = $Sp; principalType = 'ServicePrincipal'; principalDisplayName = $Sp; resourceId = $Resource; appRoleId = $RoleId } }
}

Describe 'Measure-CIPPOAuthGrantRisk' {
    It 'scores app-only full_access_as_app as Critical with a tenant-wide blast radius, and resolves the role name' {
        $R = Invoke-RiskMeasure -Sps @(New-Sp 'b1' 'Veeam Backup for Microsoft 365') -Assignments @(New-Assignment 'b1' 'exo' 'dc890d15-9560-4a4c-9b7f-a736ec74ec40')
        $R.Count | Should -Be 1
        $R[0].Risk | Should -Be 'Critical'
        $R[0].HighRiskPermissions | Should -Be @('full_access_as_app')
        $R[0].ApplicationPermissions | Should -Be @('Office 365 Exchange Online: full_access_as_app')
        $R[0].ConsentScope | Should -Be 'App-only'
        $R[0].BlastRadius | Should -Match 'every mailbox in the tenant.*without a user signed in'
        $R[0].SuggestedAction | Should -Match 'accountEnabled=false'
        $R[0].SuggestedAction | Should -Match 'allow-list'
    }

    It 'treats Microsoft first-party apps as Low and unscored' {
        $Sp = New-Sp 'm1' 'Microsoft Exchange Online Protection' -Owner 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
        $R = Invoke-RiskMeasure -Sps @($Sp) -Assignments @(New-Assignment 'm1' 'exo' 'dc890d15-9560-4a4c-9b7f-a736ec74ec40')
        $R[0].IsMicrosoft | Should -BeTrue
        $R[0].Risk | Should -Be 'Low'
        $R[0].Score | Should -Be 0
        $R[0].Publisher | Should -Be 'Microsoft'
        $R[0].SuggestedAction | Should -BeNullOrEmpty
    }

    It 'scores tenant-wide delegated Mail.Read as High and a single user grant as Medium' {
        $Sps = @((New-Sp 'c1' 'Tenant Wide Tool'), (New-Sp 'c2' 'One User Tool'))
        $Grants = @(
            [pscustomobject]@{ clientId = 'c1'; consentType = 'AllPrincipals'; principalId = $null; resourceId = 'graph'; scope = 'User.Read Mail.Read' }
            [pscustomobject]@{ clientId = 'c2'; consentType = 'Principal'; principalId = 'u1'; resourceId = 'graph'; scope = ' Mail.Read User.Read ' }
        )
        $R = Invoke-RiskMeasure -Sps $Sps -Grants $Grants
        $Wide = $R | Where-Object DisplayName -EQ 'Tenant Wide Tool'
        $One = $R | Where-Object DisplayName -EQ 'One User Tool'
        $Wide.Risk | Should -Be 'High'
        $Wide.TenantWideConsent | Should -BeTrue
        $Wide.BlastRadius | Should -Match 'any user who signs in to it'
        $One.Risk | Should -Be 'Medium'
        $One.DelegatedUserCount | Should -Be 1
        $One.ConsentScope | Should -Be '1 user'
        $One.DelegatedPermissions | Should -Contain 'Microsoft Graph: Mail.Read (1 user)'
        $R[0].DisplayName | Should -Be 'Tenant Wide Tool'
    }

    It 'raises per-user grants with the number of consenting users' {
        $Grants = 1..15 | ForEach-Object { [pscustomobject]@{ clientId = 'c1'; consentType = 'Principal'; principalId = "u$_"; resourceId = 'graph'; scope = 'Files.Read.All' } }
        $R = Invoke-RiskMeasure -Sps @(New-Sp 'c1' 'Popular Tool') -Grants $Grants
        $R[0].DelegatedUserCount | Should -Be 15
        $R[0].Score | Should -Be 60
        $R[0].Risk | Should -Be 'High'
        $R[0].BlastRadius | Should -Match 'the 15 users who consented'
    }

    It 'adds for an unverified publisher, but not for an app registered in the tenant itself' {
        $Grant = { param($c) [pscustomobject]@{ clientId = $c; consentType = 'Principal'; principalId = 'u1'; resourceId = 'graph'; scope = 'Mail.Read' } }
        $R = Invoke-RiskMeasure -Sps @((New-Sp 'c1' 'Shady' -Verified $null -PublisherName 'Shady'), (New-Sp 'c2' 'Our Script' -Verified $null -Owner 'home')) -Grants @((& $Grant 'c1'), (& $Grant 'c2'))
        ($R | Where-Object DisplayName -EQ 'Shady').Score | Should -Be 52
        ($R | Where-Object DisplayName -EQ 'Shady').Reasons -join ' ' | Should -Match 'not verified'
        ($R | Where-Object DisplayName -EQ 'Our Script').Score | Should -Be 32
        ($R | Where-Object DisplayName -EQ 'Our Script').Reasons -join ' ' | Should -Match 'Registered in this tenant'
    }

    It 'counts offline_access only next to a high-risk delegated scope' {
        $G = @(
            [pscustomobject]@{ clientId = 'c1'; consentType = 'AllPrincipals'; resourceId = 'graph'; scope = 'Mail.Read offline_access' }
            [pscustomobject]@{ clientId = 'c2'; consentType = 'AllPrincipals'; resourceId = 'graph'; scope = 'User.Read offline_access openid' }
        )
        $R = Invoke-RiskMeasure -Sps @((New-Sp 'c1' 'Reader'), (New-Sp 'c2' 'Sign In Only')) -Grants $G
        ($R | Where-Object DisplayName -EQ 'Reader').Score | Should -Be 75
        ($R | Where-Object DisplayName -EQ 'Sign In Only').Score | Should -Be 0
        ($R | Where-Object DisplayName -EQ 'Sign In Only').Risk | Should -Be 'Low'
    }

    It 'flags an AI connector with mail access and raises it' {
        $G = @([pscustomobject]@{ clientId = 'c1'; consentType = 'Principal'; principalId = 'u1'; resourceId = 'graph'; scope = 'Mail.Read' })
        $R = Invoke-RiskMeasure -Sps @(New-Sp 'c1' 'ChatGPT Connector') -Grants $G
        $R[0].IsAiConnector | Should -BeTrue
        $R[0].AiTool | Should -Be 'ChatGPT'
        $R[0].DataPermissions | Should -Be @('Mail.Read')
        $R[0].Score | Should -Be 47
        $R[0].Reasons -join ' ' | Should -Match 'AI connector'
    }

    It 'matches short AI catalog names only as whole words' {
        $G = @([pscustomobject]@{ clientId = 'c1'; consentType = 'Principal'; principalId = 'u1'; resourceId = 'graph'; scope = 'User.Read' })
        (Invoke-RiskMeasure -Sps @(New-Sp 'c1' 'Gongfu Payroll') -Grants $G)[0].IsAiConnector | Should -BeFalse
        (Invoke-RiskMeasure -Sps @(New-Sp 'c1' 'Gong for Outlook') -Grants $G)[0].IsAiConnector | Should -BeTrue
    }

    It 'halves the score of a disabled service principal' {
        $R = Invoke-RiskMeasure -Sps @(New-Sp 'b1' 'Old Backup' -Enabled $false) -Assignments @(New-Assignment 'b1' 'exo' 'dc890d15-9560-4a4c-9b7f-a736ec74ec40')
        $R[0].Score | Should -Be 50
        $R[0].Risk | Should -Be 'Medium'
        $R[0].AccountEnabled | Should -BeFalse
        $R[0].SuggestedAction | Should -Match 'Already disabled'
    }

    It 'uses RiskyPermissions.json for permissions outside the CIPP-11 list' {
        $Ca = [pscustomobject]@{ id = 'ca-role'; value = 'Policy.ReadWrite.ConditionalAccess' }
        $GraphWithCa = [pscustomobject]@{ id = 'graph'; appId = $script:Graph.appId; displayName = 'Microsoft Graph'; appRoles = @($script:Graph.appRoles + $Ca) }
        $R = Measure-CIPPOAuthGrantRisk -ServicePrincipals @(New-Sp 'c1' 'CA Tool') -ResourceServicePrincipals @($GraphWithCa) -AppRoleAssignments @(New-Assignment 'c1' 'graph' 'ca-role') -RiskyPermissions $script:Risky
        $R[0].HighRiskPermissions | Should -Be @('Policy.ReadWrite.ConditionalAccess')
        $R[0].Risk | Should -Be 'Critical'
        # User.Read.All is not risky anywhere.
        (Invoke-RiskMeasure -Sps @(New-Sp 'c2' 'Reader') -Assignments @(New-Assignment 'c2' 'graph' 'df021288-bdef-4463-88db-98f22de89214'))[0].Risk | Should -Be 'Low'
    }

    It 'counts RiskyPermissions.json High entries as medium, not Critical' {
        $Dm = [pscustomobject]@{ id = 'dm-role'; value = 'DeviceManagementConfiguration.ReadWrite.All' }
        $GraphWithDm = [pscustomobject]@{ id = 'graph'; appId = $script:Graph.appId; displayName = 'Microsoft Graph'; appRoles = @($Dm) }
        $R = Measure-CIPPOAuthGrantRisk -ServicePrincipals @(New-Sp 'c1' 'Intune Doc Sync' -Verified $null) -ResourceServicePrincipals @($GraphWithDm) -AppRoleAssignments @(New-Assignment 'c1' 'graph' 'dm-role') -RiskyPermissions $script:Risky
        $R[0].HighRiskPermissions | Should -BeNullOrEmpty
        $R[0].Score | Should -Be 30
        $R[0].Risk | Should -Be 'Medium'
        $R[0].Reasons -join ' ' | Should -Match 'Medium-risk permissions: DeviceManagementConfiguration.ReadWrite.All'
    }

    It 'labels apps from the personal Microsoft account (consumer) tenant, which Graph calls "Microsoft Accounts"' {
        $Sp = New-Sp 'c1' 'QuickBooks Desktop' -Owner '9188040d-6c67-4c5b-b112-36a304b66dad' -Verified $null -PublisherName 'Microsoft Accounts'
        $G = @([pscustomobject]@{ clientId = 'c1'; consentType = 'Principal'; principalId = 'u1'; resourceId = 'graph'; scope = 'Mail.Send' })
        $R = Invoke-RiskMeasure -Sps @($Sp) -Grants $G
        $R[0].IsMicrosoft | Should -BeFalse
        $R[0].Publisher | Should -Be 'Personal Microsoft account app'
        $R[0].Score | Should -Be 52
        $R[0].Reasons -join ' ' | Should -Match 'not Microsoft'
    }

    It 'adds multiple high-risk scopes, capped' {
        $A = @(
            New-Assignment 'b1' 'exo' 'dc890d15-9560-4a4c-9b7f-a736ec74ec40'
            New-Assignment 'b1' 'graph' '810c84a8-4a9e-49e6-bf7d-12d183f40d01'
            New-Assignment 'b1' 'graph' '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'
        )
        $R = Invoke-RiskMeasure -Sps @(New-Sp 'b1' 'Everything') -Assignments $A
        $R[0].Score | Should -Be 110
        $R[0].BlastRadius | Should -Match 'Global Administrator'
    }

    It 'reads last sign-in as a client, and treats unreadable activity as unknown rather than unused' {
        $A = @(New-Assignment 'b1' 'exo' 'dc890d15-9560-4a4c-9b7f-a736ec74ec40')
        $Unknown = Invoke-RiskMeasure -Sps @(New-Sp 'b1' 'Backup') -Assignments $A
        $Unknown[0].SignInKnown | Should -BeFalse
        $Unknown[0].Score | Should -Be 100

        $Act = @([pscustomobject]@{ appId = 'app-b1'; lastSignInActivity = @{ lastSignInDateTime = '2026-10-30T00:00:00Z' }; delegatedClientSignInActivity = @{ lastSignInDateTime = $null }; applicationAuthenticationClientSignInActivity = @{ lastSignInDateTime = '2026-05-01T00:00:00Z' } })
        $Stale = Invoke-RiskMeasure -Sps @(New-Sp 'b1' 'Backup') -Assignments $A -SignIns $Act
        $Stale[0].SignInKnown | Should -BeTrue
        $Stale[0].LastSignIn.ToString('yyyy-MM-dd') | Should -Be '2026-05-01'
        $Stale[0].Score | Should -Be 105

        $Never = Invoke-RiskMeasure -Sps @(New-Sp 'b1' 'Backup') -Assignments $A -SignIns @()
        $Never[0].SignInKnown | Should -BeTrue
        $Never[0].Reasons -join ' ' | Should -Match 'No recorded sign-in'
    }

    It 'ignores app role assignments to users and groups' {
        $A = @([pscustomobject]@{ principalId = 'u1'; principalType = 'User'; resourceId = 'exo'; appRoleId = 'dc890d15-9560-4a4c-9b7f-a736ec74ec40' })
        Invoke-RiskMeasure -Sps @() -Assignments $A | Should -BeNullOrEmpty
    }
}
