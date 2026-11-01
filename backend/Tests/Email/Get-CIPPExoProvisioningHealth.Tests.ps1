# Pester tests for Get-CIPPExoProvisioningHealth (Vikunja CIPP-36).
# Pins each check's Pass/Warn/Fail/Info rules, that checks fail soft, that a tenant without an Exchange licence is
# Info rather than Fail, that a licensed tenant whose Exchange does not answer is Fail even when the error reads like a
# licence error, and the grace period / guest / non-mailbox-plan filtering of the licensed-users check.
# Graph and EXO are stubbed; fixtures go through JSON so dates come back re-typed as [datetime], as they do live.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Modules = Join-Path $RepoRoot 'Modules'
    foreach ($Name in 'Get-CIPPExoProvisioningHealth.ps1', 'Get-CIPPAlertFailureSeverity.ps1') {
        $Path = Get-ChildItem -Path $Modules -Recurse -Filter $Name -File | Select-Object -First 1 -ExpandProperty FullName
        if (-not $Path) { throw "Could not locate $Name" }
        . $Path
    }

    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $AsApp, [switch]$ComplexFilter) }
    function New-ExoRequest { [CmdletBinding()] param($tenantid, $cmdlet, $cmdParams, $Select, $Anchor, $useSystemMailbox) }
    function Get-CippException { [CmdletBinding()] param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }

    $script:SavedRoot = $env:CIPPRootPath
    $env:CIPPRootPath = $RepoRoot
    $script:OrgRoles = @(Get-Content -Path (Join-Path (Join-Path $RepoRoot 'Config') 'OrganizationManagementRoles.json') -Raw | ConvertFrom-Json)

    $script:Now = [datetime]::UtcNow
    function script:AgoH([double]$Hours) { $script:Now.AddHours(-$Hours).ToString('yyyy-MM-ddTHH:mm:ssZ') }
    # -InputObject keeps a one-item list a JSON array; ConvertFrom-Json then emits the items one by one.
    function script:Json($Value) { ConvertTo-Json -InputObject @($Value) -Depth 8 | ConvertFrom-Json }

    $script:StdPlan = '9aaf7827-d63c-4b61-89c3-182f06f82e5c'
    $script:FoundationPlan = '113feb6c-3fe4-4440-bddc-54d774bf0318'

    function script:New-User {
        param([string]$Id, [string]$Type = 'Member', [double]$CreatedHoursAgo = 2400, [Nullable[double]]$PlanHoursAgo = 720, [string]$PlanId = $script:StdPlan, [string]$PlanStatus = 'Enabled')
        $Plans = @()
        if ($null -ne $PlanHoursAgo) { $Plans += @{ assignedDateTime = (AgoH $PlanHoursAgo); capabilityStatus = $PlanStatus; service = 'exchange'; servicePlanId = $PlanId } }
        [ordered]@{ id = $Id; displayName = "User $Id"; userPrincipalName = "$Id@contoso.com"; userType = $Type; createdDateTime = (AgoH $CreatedHoursAgo); assignedPlans = $Plans }
    }

    function script:Set-Fixture {
        $script:F = @{
            Throw       = @{}
            Skus        = @(
                [ordered]@{ skuPartNumber = 'SPB'; capabilityStatus = 'Enabled'; servicePlans = @(
                        @{ servicePlanId = $script:StdPlan; servicePlanName = 'EXCHANGE_S_STANDARD'; provisioningStatus = 'Success' }
                        @{ servicePlanId = $script:FoundationPlan; servicePlanName = 'EXCHANGE_S_FOUNDATION'; provisioningStatus = 'Success' }
                        @{ servicePlanId = '176a09a6-7ec5-4039-ac02-b2791c6ba793'; servicePlanName = 'EXCHANGE_S_ARCHIVE_ADDON'; provisioningStatus = 'Success' }
                    )
                }
            )
            OrgCreated  = (AgoH 9000)
            OrgConfig   = [ordered]@{ Name = 'contoso.onmicrosoft.com'; IsDehydrated = $false; IsValid = $true; AdminDisplayVersion = '0.20 (15.21.569.8)' }
            RoleGroups  = @('Organization Management', 'Recipient Management', 'View-Only Organization Management', 'Help Desk', 'Hygiene Management', 'Compliance Management', 'Discovery Management', 'Records Management', 'Security Administrator', 'Security Reader', 'Custom Group')
            Roles       = @('Mail Recipient Creation', 'Mail Recipients', 'Organization Configuration', 'Role Management', 'Remote and Accepted Domains', 'Distribution Groups', 'Reset Password', 'User Options', 'View-Only Configuration', 'View-Only Recipients', 'Legal Hold')
            Definitions = @($script:OrgRoles)
            Assigned    = @($script:OrgRoles)
            Accepted    = @('contoso.com', 'contoso.onmicrosoft.com', 'contoso.mail.onmicrosoft.com')
            Domains     = @(
                [ordered]@{ id = 'contoso.com'; isVerified = $true; isInitial = $false; supportedServices = @('Email', 'OfficeCommunicationsOnline') }
                [ordered]@{ id = 'contoso.onmicrosoft.com'; isVerified = $true; isInitial = $true; supportedServices = @('Email') }
                [ordered]@{ id = 'contoso.mail.onmicrosoft.com'; isVerified = $true; isInitial = $false; supportedServices = @() }
                [ordered]@{ id = 'pending.com'; isVerified = $false; isInitial = $false; supportedServices = @('Email') }
            )
            Users       = @(
                (New-User -Id 'aaaaaaaa-0000-0000-0000-000000000001')
                # Only EXCHANGE_S_FOUNDATION: service "exchange" but no mailbox right.
                (New-User -Id 'aaaaaaaa-0000-0000-0000-000000000002' -PlanId $script:FoundationPlan)
                # Licensed guest: guests do not get a mailbox in the resource tenant.
                (New-User -Id 'aaaaaaaa-0000-0000-0000-000000000003' -Type 'Guest')
                # Licensed two hours ago: inside the 24 h grace period.
                (New-User -Id 'aaaaaaaa-0000-0000-0000-000000000004' -PlanHoursAgo 2)
                # Old account, licence suspended.
                (New-User -Id 'aaaaaaaa-0000-0000-0000-000000000005' -PlanStatus 'Suspended')
            )
            # EXO reports the id upper-cased here to pin the case-insensitive match.
            Recipients  = @(@{ ExternalDirectoryObjectId = 'AAAAAAAA-0000-0000-0000-000000000001'; RecipientTypeDetails = 'UserMailbox' })
        }
    }

    function script:Row($Result, [string]$Check) { @($Result.Checks | Where-Object Check -EQ $Check) | Select-Object -First 1 }
}

AfterAll {
    $env:CIPPRootPath = $script:SavedRoot
}

Describe 'Get-CIPPExoProvisioningHealth' {
    BeforeEach {
        Set-Fixture
        Mock New-GraphGetRequest {
            foreach ($Key in $script:F.Throw.Keys) { if ($uri -like "*$Key*") { throw $script:F.Throw[$Key] } }
            if ($uri -like '*/subscribedSkus*') { return (Json $script:F.Skus) }
            if ($uri -like '*/organization*') { return (Json @([ordered]@{ id = 'tid'; createdDateTime = $script:F.OrgCreated })) }
            if ($uri -like '*roleManagement/exchange/roleDefinitions*') { return @($script:F.Definitions | ForEach-Object { [pscustomobject]@{ id = [guid]::NewGuid().ToString(); displayName = $_ } }) }
            if ($uri -like '*/domains*') { return (Json $script:F.Domains) }
            if ($uri -like '*/users*') { return (Json $script:F.Users) }
            throw "unexpected GET $uri"
        }
        Mock New-ExoRequest {
            if ($script:F.Throw.ContainsKey($cmdlet)) { throw $script:F.Throw[$cmdlet] }
            switch ($cmdlet) {
                'Get-OrganizationConfig' { return [pscustomobject]$script:F.OrgConfig }
                'Get-RoleGroup' { return @($script:F.RoleGroups | ForEach-Object { [pscustomobject]@{ Name = $_ } }) }
                'Get-ManagementRole' { return @($script:F.Roles | ForEach-Object { [pscustomobject]@{ Name = $_ } }) }
                'Get-ManagementRoleAssignment' {
                    $script:AssignmentParams = $cmdParams
                    $Rows = @($script:F.Assigned | ForEach-Object { [pscustomobject]@{ Role = $_; RoleAssigneeName = 'Organization Management' } })
                    return @($Rows + [pscustomobject]@{ Role = 'Not counted'; RoleAssigneeName = 'Help Desk' })
                }
                'Get-AcceptedDomain' { return @($script:F.Accepted | ForEach-Object { [pscustomobject]@{ DomainName = $_; DomainType = 'Authoritative' } }) }
                'Get-Recipient' { $script:RecipientParams = $cmdParams; return @($script:F.Recipients | ForEach-Object { [pscustomobject]$_ }) }
            }
            throw "unexpected cmdlet $cmdlet"
        }
    }

    It 'passes a healthy tenant and only counts mailbox-plan members past the grace period' {
        $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
        $R.Summary.Overall | Should -Be 'Pass'
        @($R.Checks | Where-Object { $_.Status -in 'Fail', 'Warn' }).Count | Should -Be 0
        (Row $R 'LicensedUserMailboxes').Detail | Should -BeLike 'All 1 users*'
        (Row $R 'ExchangeLicence').Detail | Should -Not -Match 'FOUNDATION|ARCHIVE'
        @($R.Checks.Check) | Should -Not -Contain 'OrganizationCustomization'
        $R.Summary.RepairSuggested | Should -BeFalse
        $script:RecipientParams.ResultSize | Should -Be 'Unlimited'
        $script:AssignmentParams.Delegating | Should -BeFalse
    }

    It 'returns every check as a row with Check, Status, Detail and Fix' {
        $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
        @($R.Checks.Check) | Should -Be @('ExchangeLicence', 'OrganizationConfig', 'RoleGroups', 'ManagementRoles', 'OrgManagementRoles', 'AcceptedDomains', 'LicensedUserMailboxes')
        foreach ($C in $R.Checks) { $C.PSObject.Properties.Name | Should -Contain 'Fix' }
    }

    Context 'Licensed users without a mailbox' {
        It 'warns per user past the grace period, skipping guests, non-mailbox plans and users inside the grace period' {
            $script:F.Users += (New-User -Id 'bbbbbbbb-0000-0000-0000-000000000001')
            # Old account licensed recently: the grace period runs from the licence, not the account.
            $script:F.Users += (New-User -Id 'bbbbbbbb-0000-0000-0000-000000000002' -CreatedHoursAgo 9000 -PlanHoursAgo 3)
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            (Row $R 'LicensedUserMailboxes').Status | Should -Be 'Warn'
            @($R.UsersWithoutMailbox.id) | Should -Be @('bbbbbbbb-0000-0000-0000-000000000001')
            $R.UsersWithoutMailbox[0].licensedSince | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        }

        It 'honours a custom grace period' {
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com' -GraceHours 1
            @($R.UsersWithoutMailbox.id) | Should -Be @('aaaaaaaa-0000-0000-0000-000000000004')
        }

        It 'fails when no licensed user has a mailbox' {
            $script:F.Recipients = @()
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            (Row $R 'LicensedUserMailboxes').Status | Should -Be 'Fail'
            $R.Summary.Overall | Should -Be 'Fail'
        }

        It 'treats a licensed mail user (hybrid) as present and notes it' {
            $script:F.Users += (New-User -Id 'cccccccc-0000-0000-0000-000000000001')
            $script:F.Recipients += @{ ExternalDirectoryObjectId = 'cccccccc-0000-0000-0000-000000000001'; RecipientTypeDetails = 'MailUser' }
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            (Row $R 'LicensedUserMailboxes').Status | Should -Be 'Pass'
            (Row $R 'LicensedUserMailboxes').Detail | Should -Match '1 licensed user\(s\) are mail users'
            @($R.LicensedMailUsers.id) | Should -Be @('cccccccc-0000-0000-0000-000000000001')
        }
    }

    Context 'Organization Management roles' {
        It 'fails with 5 or more missing roles and points to the existing role repair without calling it' {
            $script:F.Assigned = @($script:OrgRoles | Select-Object -Skip 6)
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            $Row = Row $R 'OrgManagementRoles'
            $Row.Status | Should -Be 'Fail'
            $Row.Fix | Should -Match 'ExecExchangeRoleRepair'
            @($R.MissingOrgManagementRoles).Count | Should -Be 6
            $R.Summary.RepairSuggested | Should -BeTrue
            Should -Invoke New-GraphGetRequest -Times 0 -ParameterFilter { $uri -like '*roleAssignments*' }
        }

        It 'warns with 1 to 4 missing roles and ignores roles the tenant has no definition for' {
            $script:F.Assigned = @($script:OrgRoles | Select-Object -Skip 2)
            $script:F.Definitions = @($script:OrgRoles | Select-Object -Skip 1)
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            (Row $R 'OrgManagementRoles').Status | Should -Be 'Warn'
            @($R.MissingOrgManagementRoles) | Should -Be @($script:OrgRoles[1])
        }
    }

    Context 'Role groups, management roles, organisation' {
        It 'fails when Exchange returns no role groups and warns when one built-in group is missing' {
            $script:F.RoleGroups = @()
            (Row (Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com') 'RoleGroups').Status | Should -Be 'Fail'
            Set-Fixture
            $script:F.RoleGroups = @($script:F.RoleGroups | Where-Object { $_ -ne 'Help Desk' })
            $Row = Row (Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com') 'RoleGroups'
            $Row.Status | Should -Be 'Warn'
            $Row.Detail | Should -Match 'Help Desk'
        }

        It 'fails when a core management role is missing' {
            $script:F.Roles = @($script:F.Roles | Where-Object { $_ -ne 'Mail Recipient Creation' })
            (Row (Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com') 'ManagementRoles').Status | Should -Be 'Fail'
        }

        It 'adds an Info row for a dehydrated organisation without failing it' {
            $script:F.OrgConfig.IsDehydrated = $true
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            (Row $R 'OrganizationCustomization').Status | Should -Be 'Info'
            $R.Summary.Overall | Should -Be 'Pass'
        }
    }

    Context 'Accepted domains' {
        It 'warns per verified email domain missing from Exchange, case-insensitively, ignoring non-email and unverified domains' {
            $script:F.Domains += [ordered]@{ id = 'Fabrikam.com'; isVerified = $true; isInitial = $false; supportedServices = @('Email') }
            $script:F.Domains += [ordered]@{ id = 'E8VDW.smtp.exclaimer.cloud'; isVerified = $true; isInitial = $false; supportedServices = @('Email') }
            $script:F.Accepted += 'e8vdw.SMTP.exclaimer.cloud'
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            (Row $R 'AcceptedDomains').Status | Should -Be 'Warn'
            @($R.MissingDomains) | Should -Be @('fabrikam.com')
        }

        It 'fails when the onmicrosoft.com domain is not accepted' {
            $script:F.Accepted = @('contoso.com')
            (Row (Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com') 'AcceptedDomains').Status | Should -Be 'Fail'
        }
    }

    Context 'Licensing and Exchange not answering' {
        It 'fails a licensed tenant whose Exchange does not answer, even when the error reads like a licence error' {
            $script:F.Throw['Get-OrganizationConfig'] = 'The tenant is not provisioned for Exchange Online'
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            $Row = Row $R 'OrganizationConfig'
            $Row.Status | Should -Be 'Fail'
            $Row.Errored | Should -BeTrue
            $R.Summary.NoExchangeLicence | Should -BeFalse
            foreach ($Name in 'RoleGroups', 'ManagementRoles', 'OrgManagementRoles', 'AcceptedDomains', 'LicensedUserMailboxes') {
                (Row $R $Name).Status | Should -Be 'Info'
            }
            Should -Invoke New-ExoRequest -Times 0 -ParameterFilter { $cmdlet -eq 'Get-RoleGroup' }
        }

        It 'only warns while the tenant is younger than the grace period' {
            $script:F.Throw['Get-OrganizationConfig'] = 'Access denied'
            $script:F.OrgCreated = (AgoH 3)
            (Row (Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com') 'OrganizationConfig').Status | Should -Be 'Warn'
        }

        It 'reports Info, not Fail, for a tenant with no mailbox licence and no Exchange' {
            $script:F.Skus = @([ordered]@{ skuPartNumber = 'POWER_BI_STANDARD'; capabilityStatus = 'Enabled'; servicePlans = @(@{ servicePlanId = $script:FoundationPlan; servicePlanName = 'EXCHANGE_S_FOUNDATION'; provisioningStatus = 'Success' }) })
            $script:F.Throw['Get-OrganizationConfig'] = 'Something unexpected'
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            @($R.Checks | Where-Object { $_.Status -in 'Fail', 'Warn' }).Count | Should -Be 0
            (Row $R 'ExchangeLicence').Status | Should -Be 'Info'
            (Row $R 'OrganizationConfig').Detail | Should -Match 'No Exchange licence'
            $R.Summary.NoExchangeLicence | Should -BeTrue
            $R.Summary.Overall | Should -Be 'Info'
        }

        It 'ignores mailbox plans in suspended SKUs and disabled plans' {
            $script:F.Skus = @(
                [ordered]@{ skuPartNumber = 'EXCHANGESTANDARD'; capabilityStatus = 'Suspended'; servicePlans = @(@{ servicePlanId = $script:StdPlan; servicePlanName = 'EXCHANGE_S_STANDARD'; provisioningStatus = 'Success' }) }
                [ordered]@{ skuPartNumber = 'EXCHANGEENTERPRISE'; capabilityStatus = 'Enabled'; servicePlans = @(@{ servicePlanId = 'efb87545-963c-4e0d-99df-69c6916d9eb0'; servicePlanName = 'EXCHANGE_S_ENTERPRISE'; provisioningStatus = 'Disabled' }) }
            )
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            (Row $R 'ExchangeLicence').Status | Should -Be 'Info'
            # Exchange still answered, so the RBAC and domain checks ran; the mailbox comparison is skipped.
            (Row $R 'RoleGroups').Status | Should -Be 'Pass'
            (Row $R 'LicensedUserMailboxes').Detail | Should -BeLike 'Skipped*'
        }

        It 'warns while a mailbox plan is still provisioning and fails on a provisioning error' {
            $script:F.Skus[0].servicePlans[0].provisioningStatus = 'PendingProvisioning'
            (Row (Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com') 'ExchangeLicence').Status | Should -Be 'Warn'
            $script:F.Skus[0].servicePlans[0].provisioningStatus = 'Error'
            (Row (Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com') 'ExchangeLicence').Status | Should -Be 'Fail'
        }

        It 'learns mailbox plan ids from the tenant subscriptions' {
            $NewPlan = 'dddddddd-0000-0000-0000-000000000001'
            $script:F.Skus += [ordered]@{ skuPartNumber = 'Microsoft_365_E7'; capabilityStatus = 'Enabled'; servicePlans = @(@{ servicePlanId = $NewPlan; servicePlanName = 'EXCHANGE_S_ENTERPRISE_E7'; provisioningStatus = 'Success' }) }
            $script:F.Users += (New-User -Id 'eeeeeeee-0000-0000-0000-000000000001' -PlanId $NewPlan)
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            @($R.UsersWithoutMailbox.id) | Should -Be @('eeeeeeee-0000-0000-0000-000000000001')
        }
    }

    Context 'Fail soft' {
        It 'keeps running the other checks when one EXO read fails' {
            $script:F.Throw['Get-RoleGroup'] = 'Throttled'
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            $Row = Row $R 'RoleGroups'
            $Row.Status | Should -Be 'Warn'
            $Row.Errored | Should -BeTrue
            $Row.Detail | Should -Match 'Throttled'
            (Row $R 'ManagementRoles').Status | Should -Be 'Pass'
            (Row $R 'LicensedUserMailboxes').Status | Should -Be 'Pass'
            @($R.Errors) | Should -Contain 'Get-RoleGroup: Throttled'
        }

        It 'falls back to the known mailbox plan ids when the subscriptions cannot be read' {
            $script:F.Throw['subscribedSkus'] = 'Forbidden'
            $script:F.Users += (New-User -Id 'ffffffff-0000-0000-0000-000000000001')
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            (Row $R 'ExchangeLicence').Errored | Should -BeTrue
            @($R.UsersWithoutMailbox.id) | Should -Be @('ffffffff-0000-0000-0000-000000000001')
        }

        It 'does not fail when the role definitions cannot be read' {
            $script:F.Throw['roleDefinitions'] = 'Insufficient privileges'
            $R = Get-CIPPExoProvisioningHealth -TenantFilter 'contoso.com'
            (Row $R 'OrgManagementRoles').Status | Should -Be 'Warn'
            (Row $R 'AcceptedDomains').Status | Should -Be 'Pass'
        }
    }
}
