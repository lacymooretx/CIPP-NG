# Pester tests for the Vendor Access report (Aspendora fork): item classification, stale/unknown sign-in,
# snapshot new/removed tracking, the weekly Monday 07:00 Central guard and the email.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Dir = Join-Path $RepoRoot 'Modules/CIPPCore/Public/VendorAccess'
    foreach ($F in Get-ChildItem $Dir -Filter '*.ps1') { . $F.FullName }

    $script:TenantId = '11111111-1111-1111-1111-111111111111'
    $script:PartnerId = '22222222-2222-2222-2222-222222222222'
    $script:MsId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
    $script:VendorId = '33333333-3333-3333-3333-333333333333'
    $script:Pax8Id = '3de67d67-88e8-42c0-88ea-13bfc2fc2f55'
    $script:UnknownId = '44444444-4444-4444-4444-444444444444'
    $env:TenantID = $script:PartnerId
    $script:Now = [datetime]::UtcNow
    function U { param($Iso) [datetime]::SpecifyKind([datetime]::Parse($Iso, [cultureinfo]::InvariantCulture), 'Utc') }

    function Get-Tenants {
        param($TenantFilter, [switch]$IncludeErrors)
        $All = @(
            [pscustomobject]@{ defaultDomainName = 'contoso.com'; displayName = 'Contoso'; customerId = $script:TenantId }
            [pscustomobject]@{ defaultDomainName = 'fabrikam.com'; displayName = 'Fabrikam'; customerId = '55555555-5555-5555-5555-555555555555' }
        )
        if ($TenantFilter) { $All | Where-Object defaultDomainName -EQ $TenantFilter } else { $All }
    }
    function Get-CIPPVendorTenantMap {
        $M = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $M[$script:MsId] = [pscustomobject]@{ Name = 'Microsoft'; Company = 'Microsoft'; VendorType = 'Microsoft' }
        $M[$script:VendorId] = [pscustomobject]@{ Name = 'BackupCo'; Company = 'BackupCo Inc'; VendorType = 'MSP' }
        $M
    }
    function Get-CIPPAppPermissionExposure {
        param($TenantFilter, [switch]$Live)
        [pscustomobject]@{ ServicePrincipalId = 'sp-vendor'; Risk = 'Critical'; RiskReasons = @('Mail.ReadWrite application'); Permissions = 'Microsoft Graph: Mail.ReadWrite (Application, suspicion High, impact Critical)'; PermissionCount = 1
            CredentialDetails = @([pscustomobject]@{ Purpose = 'Sign-in'; Expired = $false; AddedDateTime = $script:Now.AddDays(-3) }) }
    }
    function New-CIPPDbRequest {
        param($TenantFilter, $Type, $Fields)
        switch ($Type) {
            'ServicePrincipals' {
                [pscustomobject]@{ id = 'sp-ms'; appId = 'a-ms'; displayName = 'Office'; appOwnerOrganizationId = $script:MsId; accountEnabled = $true }
                [pscustomobject]@{ id = 'sp-own'; appId = 'a-own'; displayName = 'Own app'; appOwnerOrganizationId = $script:TenantId; accountEnabled = $true }
                [pscustomobject]@{ id = 'sp-mi'; appId = 'a-mi'; displayName = 'func'; appOwnerOrganizationId = $script:UnknownId; servicePrincipalType = 'ManagedIdentity' }
                [pscustomobject]@{ id = 'sp-vendor'; appId = 'a-vendor'; displayName = 'BackupCo Backup'; appOwnerOrganizationId = $script:VendorId; accountEnabled = $true; createdDateTime = '2025-01-01T00:00:00Z' }
                [pscustomobject]@{ id = 'sp-third'; appId = 'a-third'; displayName = 'Survey tool'; appOwnerOrganizationId = $script:UnknownId; accountEnabled = $true }
                [pscustomobject]@{ id = 'sp-idle'; appId = 'a-idle'; displayName = 'Old tool'; appOwnerOrganizationId = $script:UnknownId; accountEnabled = $false }
                [pscustomobject]@{ id = 'sp-legacy'; appId = 'f569b9c7-be15-4e87-86f7-87d30d02090b'; displayName = 'O365 LinkedIn Connection'; accountEnabled = $true }
                [pscustomobject]@{ id = 'sp-graph'; appId = '00000003-0000-0000-c000-000000000000'; displayName = 'Microsoft Graph'; appOwnerOrganizationId = $script:MsId; appRoles = @([pscustomobject]@{ id = 'r1'; value = 'User.Read.All' }) }
            }
            'AppRoleAssignments' { [pscustomobject]@{ principalId = 'sp-third'; resourceId = 'sp-graph'; appRoleId = 'r1' } }
            'OAuth2PermissionGrants' { [pscustomobject]@{ clientId = 'sp-third'; resourceId = 'sp-graph'; consentType = 'AllPrincipals'; scope = 'User.Read openid' } }
            'ServicePrincipalSignInActivities' {
                if ($script:NoP1) { return }
                [pscustomobject]@{ appId = 'a-vendor'; lastSignInActivity = @{ lastSignInDateTime = $script:Now.AddDays(-2).ToString('o') } }
                [pscustomobject]@{ appId = 'a-third'; lastSignInActivity = @{ lastSignInDateTime = $script:Now.AddDays(-50).ToString('o') } }
            }
            'Users' { [pscustomobject]@{ id = 'u-guest'; signInActivity = @{ lastSignInDateTime = $script:Now.AddDays(-10).ToString('o') } } }
        }
    }
    function Get-CIPPDbItem { param($TenantFilter, $Type) if (-not $script:NoP1) { [pscustomobject]@{ RowKey = "$Type-Count" } } }
    function New-GraphGetRequest {
        param($uri, $tenantid, $NoAuthCheck)
        if ($uri -like '*roleDefinitions*') {
            [pscustomobject]@{ id = 'ga'; templateId = '62e90394-69f5-4237-9190-012177145e10'; displayName = 'Global Administrator'; isPrivileged = $true }
            [pscustomobject]@{ id = 'hd'; templateId = 'hd'; displayName = 'Helpdesk Administrator'; isPrivileged = $true }
            [pscustomobject]@{ id = 'rd'; templateId = 'rd'; displayName = 'Directory Readers'; isPrivileged = $false }
        } elseif ($uri -like '*roleAssignments*') {
            [pscustomobject]@{ principalId = 'g-partner1'; principalOrganizationId = $script:PartnerId; roleDefinitionId = 'hd' }
            [pscustomobject]@{ principalId = 'g-partner2'; principalOrganizationId = $script:PartnerId; roleDefinitionId = 'rd' }
            [pscustomobject]@{ principalId = 'g-pax8'; principalOrganizationId = $script:Pax8Id; roleDefinitionId = 'ga' }
            [pscustomobject]@{ principalId = 'u-guest'; principalOrganizationId = $script:TenantId; roleDefinitionId = 'hd' }
            [pscustomobject]@{ principalId = 'u-member'; principalOrganizationId = $script:TenantId; roleDefinitionId = 'ga' }
        } elseif ($uri -like '*crossTenantAccessPolicy/partners*') {
            [pscustomobject]@{ tenantId = $script:PartnerId; isServiceProvider = $true }
            [pscustomobject]@{ tenantId = $script:Pax8Id; isServiceProvider = $true }
            [pscustomobject]@{ tenantId = $script:UnknownId; isServiceProvider = $false }
        } elseif ($uri -like '*findTenantInformationByTenantId*') {
            [pscustomobject]@{ displayName = 'PAX8 US'; defaultDomainName = 'pax8us.onmicrosoft.com' }
        }
    }
    function New-GraphBulkRequest {
        param($tenantid, $Requests, $Version)
        foreach ($R in $Requests) {
            @{ id = $R.id; status = 200; body = @{ value = @(@{ principalId = 'g-pax8'; principal = @{ '@odata.type' = '#microsoft.graph.group'; displayName = 'AdminAgents @( PAX8 US , pax8us.onmicrosoft.com )' } }) } }
        }
    }
    function New-GraphPOSTRequest {
        param($tenantid, $uri, $body)
        [pscustomobject]@{ value = @(
                [pscustomobject]@{ id = 'u-guest'; displayName = 'Vendor Tech'; userPrincipalName = 'tech_vendor.com#EXT#@contoso.onmicrosoft.com'; userType = 'Guest'; mail = 'tech@vendor.com'; accountEnabled = $true }
                [pscustomobject]@{ id = 'u-member'; displayName = 'Admin'; userPrincipalName = 'admin@contoso.com'; userType = 'Member'; accountEnabled = $true }
            ) }
    }
    function Get-CippException { param($Exception) @{ NormalizedError = "$Exception" } }
    function Write-LogMessage { param($API, $tenant, $message, $Sev, $LogData, $headers) }

    # In-memory table storage.
    $script:Tables = @{}
    function Get-CIPPTable { param($TableName) @{ TableName = $TableName } }
    function Get-CIPPAzDataTableEntity {
        param($TableName, $Filter)
        $Rows = @($script:Tables[$TableName].Values)
        if ($Filter -match "PartitionKey eq '([^']+)'") { $Pk = $Matches[1]; $Rows = @($Rows | Where-Object { $_.PartitionKey -eq $Pk }) }
        if ($Filter -match "RowKey eq '([^']+)'") { $Rk = $Matches[1]; $Rows = @($Rows | Where-Object { $_.RowKey -eq $Rk }) }
        $Rows
    }
    function Add-CIPPAzDataTableEntity {
        param($TableName, $Entity, [switch]$Force)
        if (-not $script:Tables[$TableName]) { $script:Tables[$TableName] = @{} }
        $Row = [pscustomobject]$Entity
        $Row | Add-Member -NotePropertyName Timestamp -NotePropertyValue ([datetimeoffset]::UtcNow) -Force
        $script:Tables[$TableName]["$($Entity.PartitionKey)|$($Entity.RowKey)"] = $Row
    }
    function Remove-CIPPAzDataTableEntity { param($TableName, $Entity, [switch]$Force) $script:Tables[$TableName].Remove("$($Entity.PartitionKey)|$($Entity.RowKey)") }
    $script:Sent = [System.Collections.Generic.List[object]]::new()
    function Send-CIPPAlert { param($Type, $Title, $HTMLContent, $altEmail, $TenantFilter, $APIName) $script:Sent.Add([pscustomobject]@{ To = $altEmail; Title = $Title; Html = $HTMLContent }) }
}

Describe 'Get-CIPPVendorAccessReport' {
    BeforeEach { $script:NoP1 = $false; $script:Tables = @{} }

    It 'lists foreign apps only: not Microsoft, not this tenant, not managed identities, not ownerless apps with no grants' {
        $R = Get-CIPPVendorAccessReport -TenantFilter 'contoso.com'
        $Apps = @($R.Items | Where-Object Kind -EQ 'App')
        @($Apps.Name) | Should -Be @('BackupCo Backup', 'Old tool', 'Survey tool') -Because 'sorted by risk then name; Critical first'
    }

    It 'takes risk and new credentials from the exposure report and vendor from the vendor list' {
        $R = Get-CIPPVendorAccessReport -TenantFilter 'contoso.com'
        $V = $R.Items | Where-Object Name -EQ 'BackupCo Backup'
        $V.Risk | Should -Be 'Critical'
        $V.Vendor | Should -Be 'BackupCo'
        $V.Organisation | Should -Be 'BackupCo Inc'
        $V.OrganisationType | Should -Be 'MSP vendor'
        $V.NewCredentials | Should -Be 1
        $V.SignInActivity | Should -Be 'Active'
        $V.Stale | Should -BeFalse
    }

    It 'lists every permission of an app the risky catalogue does not cover, rated Low' {
        $R = Get-CIPPVendorAccessReport -TenantFilter 'contoso.com'
        $T = $R.Items | Where-Object Name -EQ 'Survey tool'
        $T.Risk | Should -Be 'Low'
        $T.Access | Should -Match 'User.Read.All \(application\)'
        $T.Access | Should -Match 'User.Read \(delegated, all users\)'
        $T.OrganisationType | Should -Be 'Third party'
    }

    It 'flags 45+ days without sign-in as stale and no recorded sign-in as stale' {
        $R = Get-CIPPVendorAccessReport -TenantFilter 'contoso.com'
        ($R.Items | Where-Object Name -EQ 'Survey tool').Stale | Should -BeTrue
        ($R.Items | Where-Object Name -EQ 'Survey tool').DaysSinceLastSignIn | Should -Be 50
        ($R.Items | Where-Object Name -EQ 'Old tool').SignInActivity | Should -Be 'No sign-in recorded'
        ($R.Items | Where-Object Name -EQ 'Old tool').Stale | Should -BeTrue
    }

    It 'reports Unknown, never "never", without Entra ID P1 sign-in data' {
        $script:NoP1 = $true
        $R = Get-CIPPVendorAccessReport -TenantFilter 'contoso.com'
        $R.SignInActivityAvailable | Should -BeFalse
        foreach ($A in @($R.Items | Where-Object Kind -EQ 'App')) {
            $A.SignInActivity | Should -Be 'Unknown'
            $A.Stale | Should -BeNullOrEmpty
        }
    }

    It 'shows another partner''s GDAP group with Global Administrator as a Critical outside admin' {
        $R = Get-CIPPVendorAccessReport -TenantFilter 'contoso.com'
        $P = $R.Items | Where-Object { $_.Kind -eq 'ForeignRoleHolder' -and $_.OrganisationId -eq $script:Pax8Id }
        $P.Name | Should -Match 'AdminAgents'
        $P.Risk | Should -Be 'Critical'
        $P.Access | Should -Be 'Global Administrator'
        $P.Organisation | Should -Be 'PAX8 US (pax8us.onmicrosoft.com)'
    }

    It 'summarises the CIPP partner tenant''s own GDAP groups as one Low row' {
        $R = Get-CIPPVendorAccessReport -TenantFilter 'contoso.com'
        $P = @($R.Items | Where-Object { $_.Kind -eq 'ForeignRoleHolder' -and $_.OrganisationType -eq 'Partner tenant' })
        $P.Count | Should -Be 1
        $P[0].Risk | Should -Be 'Low'
        $P[0].Name | Should -Match '2 groups'
    }

    It 'lists guests holding roles (CIPP-15 rule) and not member admins' {
        $R = Get-CIPPVendorAccessReport -TenantFilter 'contoso.com'
        $G = @($R.Items | Where-Object Kind -EQ 'GuestRoleHolder')
        $G.Count | Should -Be 1
        $G[0].Risk | Should -Be 'High'
        $G[0].Organisation | Should -Be 'vendor.com'
        $G[0].DaysSinceLastSignIn | Should -Be 10
        @($R.Items | Where-Object ObjectId -EQ 'u-member').Count | Should -Be 0
    }

    It 'lists service-provider partners only' {
        $R = Get-CIPPVendorAccessReport -TenantFilter 'contoso.com'
        $S = @($R.Items | Where-Object Kind -EQ 'ServiceProvider')
        $S.Count | Should -Be 2
        ($S | Where-Object OrganisationId -EQ $script:Pax8Id).Risk | Should -Be 'Medium'
        ($S | Where-Object OrganisationId -EQ $script:PartnerId).Risk | Should -Be 'Low'
    }
}

Describe 'Vendor access snapshot' {
    BeforeEach { $script:NoP1 = $false; $script:Tables = @{} }

    It 'marks the first run as baseline, then flags later additions as new and missing items as removed' {
        $First = Update-CIPPVendorAccessSnapshot -TenantFilter 'contoso.com'
        $First.Summary.New | Should -Be 0
        $First.Summary.Removed | Should -Be 0
        $First.Summary.ThirdPartyItems | Should -BeGreaterThan 0

        # A new app appears and the survey tool is gone.
        function Get-CIPPAppPermissionExposure { param($TenantFilter, [switch]$Live) }
        $script:ExtraSp = $true
        $Orig = ${function:New-CIPPDbRequest}
        function New-CIPPDbRequest {
            param($TenantFilter, $Type, $Fields)
            if ($Type -eq 'ServicePrincipals') {
                [pscustomobject]@{ id = 'sp-vendor'; appId = 'a-vendor'; displayName = 'BackupCo Backup'; appOwnerOrganizationId = $script:VendorId; accountEnabled = $true }
                [pscustomobject]@{ id = 'sp-new'; appId = 'a-new'; displayName = 'Brand new'; appOwnerOrganizationId = $script:UnknownId; accountEnabled = $true }
                [pscustomobject]@{ id = 'sp-idle'; appId = 'a-idle'; displayName = 'Old tool'; appOwnerOrganizationId = $script:UnknownId; accountEnabled = $false }
            }
        }
        $Second = Update-CIPPVendorAccessSnapshot -TenantFilter 'contoso.com'
        ${function:New-CIPPDbRequest} = $Orig
        $New = @($Second.Items | Where-Object IsNew)
        @($New.Name) | Should -Be @('Brand new')
        $Gone = @($Second.Items | Where-Object Removed)
        @($Gone.Name) | Should -Contain 'Survey tool'
        $Second.Summary.Removed | Should -BeGreaterThan 0
        ($Second.Items | Where-Object Name -EQ 'BackupCo Backup').IsNew | Should -BeFalse
    }

    It 'does not count the CIPP partner tenant as third party' {
        $S = Update-CIPPVendorAccessSnapshot -TenantFilter 'contoso.com'
        @($S.Items | Where-Object { -not $_.IsThirdParty }).Count | Should -Be 2
        $S.Summary.ForeignRoleHolders | Should -Be 1
        $S.Summary.ServiceProviders | Should -Be 1
    }
}

Describe 'Weekly Monday 07:00 Central guard' {
    BeforeEach { $script:NoP1 = $false; $script:Tables = @{}; $script:Sent.Clear() }

    It 'is not due before 07:00 Central on a Monday (CST)' {
        Invoke-CIPPVendorAccessWeekly -Now ((U '2026-11-09T12:59:00')) | Should -Be 'Not due'
        $script:Sent.Count | Should -Be 0
    }

    It 'sends at 07:05 CST (13:05 UTC) in November, once' {
        Invoke-CIPPVendorAccessWeekly -Now ((U '2026-11-09T13:05:00')) | Should -Be 'Sent'
        Invoke-CIPPVendorAccessWeekly -Now ((U '2026-11-09T14:05:00')) | Should -Be 'Already sent'
        $script:Sent.Count | Should -Be 1
        $script:Sent[0].To | Should -Be 'lacy@aspendora.com'
    }

    It 'sends at 07:05 CDT (12:05 UTC) in July and not at 06:05 CDT' {
        Invoke-CIPPVendorAccessWeekly -Now ((U '2026-07-06T11:05:00')) | Should -Be 'Not due'
        Invoke-CIPPVendorAccessWeekly -Now ((U '2026-07-06T12:05:00')) | Should -Be 'Sent'
    }

    It 'is not due on a Tuesday, or when disabled' {
        Invoke-CIPPVendorAccessWeekly -Now ((U '2026-11-10T14:00:00')) | Should -Be 'Not due'
        Add-CIPPAzDataTableEntity -TableName 'CippVendorAccess' -Entity @{ PartitionKey = 'Settings'; RowKey = 'Weekly'; Enabled = $false }
        Invoke-CIPPVendorAccessWeekly -Now ((U '2026-11-09T14:00:00')) | Should -Be 'Disabled'
    }

    It 'uses the saved recipient' {
        Add-CIPPAzDataTableEntity -TableName 'CippVendorAccess' -Entity @{ PartitionKey = 'Settings'; RowKey = 'Weekly'; Enabled = $true; Recipient = 'soc@aspendora.com' }
        Invoke-CIPPVendorAccessWeekly -Now ((U '2026-11-16T13:30:00')) | Should -Be 'Sent'
        $script:Sent[0].To | Should -Be 'soc@aspendora.com'
    }
}

Describe 'Vendor access email' {
    BeforeEach { $script:NoP1 = $false; $script:Tables = @{}; $script:Sent.Clear() }

    It 'has a summary, the high-risk and stale lists, and a section per tenant' {
        $Html = New-CIPPVendorAccessHtml -Snapshot (Update-CIPPVendorAccessSnapshot -TenantFilter 'contoso.com')
        $Html | Should -Match 'Vendor access across client tenants'
        $Html | Should -Match 'new since last week'
        $Html | Should -Match 'High or critical risk \(3\)'
        $Html | Should -Match 'Stale: no sign-in for 45\+ days \(2\)'
        $Html | Should -Match 'Contoso \('
        $Html | Should -Match 'AdminAgents'
        $Html | Should -Not -Match '>never<'
    }

    It 'says Unknown (no Entra ID P1) instead of never' {
        $script:NoP1 = $true
        $Html = New-CIPPVendorAccessHtml -Snapshot (Update-CIPPVendorAccessSnapshot -TenantFilter 'contoso.com')
        $Html | Should -Match 'Unknown \(no Entra ID P1\)'
        $Html | Should -Match 'app sign-in data unavailable'
    }

    It 'shows times in US Central with the right abbreviation' {
        $Snap = Update-CIPPVendorAccessSnapshot -TenantFilter 'contoso.com'
        $Snap.GeneratedAt = (U '2026-11-09T13:00:00')
        New-CIPPVendorAccessHtml -Snapshot $Snap | Should -Match 'Mon Nov 9, 2026 7:00 AM CST'
    }
}
