function Get-CIPPExoProvisioningHealth {
    <#
    .SYNOPSIS
        Check that Exchange Online provisioned correctly in a tenant: organisation, RBAC, accepted domains, mailboxes.
    .DESCRIPTION
        Read only. Shared by ListExoProvisioningHealth (the Exchange Provisioning page) and the ExoProvisioning alert.
        Catches the silent failure where a new tenant or SKU (reported on E7) never gets its Exchange RBAC roles or
        organisation, which otherwise only shows up when mailbox creation breaks during onboarding.

        Checks, each failing soft so one failure does not stop the rest:
          ExchangeLicence       - mailbox service plans in the active subscriptions (subscribedSkus) and their
                                  provisioning status. No mailbox plan = Info, not Fail.
          OrganizationConfig    - Get-OrganizationConfig answers. Licensed but not answering = Fail (Warn while the
                                  tenant is younger than GraceHours). Not licensed and not answering = Info.
          OrganizationCustomization - IsDehydrated (Info only; dehydrated orgs are normal for small tenants).
          RoleGroups            - built-in role groups exist (Organization Management missing = Fail).
          ManagementRoles       - core management roles exist.
          OrgManagementRoles    - roles assigned to Organization Management, compared exactly as the Tenant Access
                                  check and ExecExchangeRoleRepair do (Config/OrganizationManagementRoles.json
                                  intersected with Graph roleManagement/exchange/roleDefinitions). 5+ missing = Fail.
          AcceptedDomains       - verified Entra domains with the Email service are accepted domains in EXO.
          LicensedUserMailboxes - members with an enabled mailbox plan for longer than GraceHours have a recipient in
                                  EXO (Get-Recipient by ExternalDirectoryObjectId). None of them = Fail.
        Remediation stays a human action: Fix text points to the Exchange role repair (ExecExchangeRoleRepair), which
        this function never calls. Aspendora fork addition (Vikunja CIPP-36).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [int]$GraceHours = 24
    )

    $Now = [datetime]::UtcNow
    $Cutoff = $Now.AddHours(-$GraceHours)
    $Checks = [System.Collections.Generic.List[object]]::new()
    $Errors = [System.Collections.Generic.List[string]]::new()
    $MissingDomains = @()
    $UsersWithoutMailbox = @()
    $MailUsers = @()
    $MissingOrgRoles = @()
    $NoExchangeLicence = $false

    $RepairFix = 'Run the Exchange role repair: the "Repair Exchange roles" button on Email > Reports > Exchange Provisioning, or CIPP > Settings > Permissions > Tenant access check > Repair Exchange Roles (POST /api/ExecExchangeRoleRepair, needs CIPP.AppSettings.ReadWrite and the RoleManagement.ReadWrite.Exchange application permission). Wait about 15 minutes for replication, then run this check again.'
    $SupportFix = 'If the tenant or SKU was added in the last day, wait and re-check. Otherwise run the Tenant access check; if Exchange still does not answer for a licensed tenant, open a Microsoft support case: the Exchange organisation did not provision.'

    # Mailbox-granting plans by name. EXCHANGE_S_FOUNDATION (in almost every SKU) and the archive add-ons do not
    # create a mailbox. Verified on aspendora.com 2026-11-01: EXCHANGE_S_STANDARD, EXCHANGE_S_ENTERPRISE,
    # EXCHANGE_S_DESKLESS; the IDs below are those three, used when subscribedSkus cannot be read.
    $MailboxPlanPattern = '^EXCHANGE_S_(?!FOUNDATION)(?!.*ARCHIVE)[A-Z0-9_]+$|^EXCHANGE_LITE$'
    $MailboxPlanIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Id in '9aaf7827-d63c-4b61-89c3-182f06f82e5c', 'efb87545-963c-4e0d-99df-69c6916d9eb0', '4a82b400-a79f-41a4-b4e2-e94f5787b113') { [void]$MailboxPlanIds.Add($Id) }

    function Add-ExoHealthRow {
        param([string]$Check, [string]$Status, [string]$Detail, [string]$Fix, [bool]$Errored = $false)
        $Checks.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail; Fix = $Fix; Errored = $Errored })
    }
    function Get-ExoHealthError($Record) {
        $Normalized = (Get-CippException -Exception $Record).NormalizedError
        if ([string]::IsNullOrWhiteSpace([string]$Normalized)) { $Normalized = [string]$Record }
        [string]$Normalized
    }
    function ConvertTo-ExoHealthUtc($Value) {
        if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
        # ConvertFrom-Json and the Graph helpers can hand back a [datetime] rather than the ISO string.
        try {
            if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
            return ([datetimeoffset]$Value).UtcDateTime
        } catch { return $null }
    }

    # --- ExchangeLicence -------------------------------------------------------------------------------------------
    # $HasMailboxPlan: $true / $false, or $null when the subscriptions could not be read.
    $HasMailboxPlan = $null
    try {
        $Skus = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,capabilityStatus,servicePlans' -tenantid $TenantFilter)
        $ActiveSkus = @($Skus | Where-Object { [string]$_.capabilityStatus -in @('Enabled', 'Warning') })
        $Plans = @(foreach ($Sku in $ActiveSkus) {
                foreach ($Plan in @($Sku.servicePlans)) {
                    if ([string]$Plan.servicePlanName -cmatch $MailboxPlanPattern) {
                        [pscustomobject]@{ Sku = [string]$Sku.skuPartNumber; Plan = [string]$Plan.servicePlanName; Id = [string]$Plan.servicePlanId; Status = [string]$Plan.provisioningStatus }
                    }
                }
            })
        foreach ($P in $Plans) { if ($P.Id) { [void]$MailboxPlanIds.Add($P.Id) } }
        $Ready = @($Plans | Where-Object Status -EQ 'Success')
        $Broken = @($Plans | Where-Object { $_.Status -eq 'Error' })
        $Pending = @($Plans | Where-Object { $_.Status -like 'Pending*' })
        $HasMailboxPlan = ($Ready.Count + $Pending.Count + $Broken.Count) -gt 0
        $Describe = { param($List) (@($List | ForEach-Object { "$($_.Plan) in $($_.Sku) ($($_.Status))" }) -join '; ') }
        if (-not $HasMailboxPlan) {
            $NoExchangeLicence = $true
            Add-ExoHealthRow -Check 'ExchangeLicence' -Status 'Info' -Detail "No Exchange Online mailbox licence: no active subscription includes a mailbox service plan. Active SKUs: $((@($ActiveSkus.skuPartNumber) | Sort-Object -Unique) -join ', ')." -Fix 'None needed unless the tenant should have Exchange. If a new SKU should include mailboxes, report its service plan names so this check can learn them.'
        } elseif ($Broken.Count -gt 0) {
            Add-ExoHealthRow -Check 'ExchangeLicence' -Status 'Fail' -Detail "Mailbox service plan provisioning failed: $(& $Describe $Broken)." -Fix $SupportFix
        } elseif ($Pending.Count -gt 0) {
            Add-ExoHealthRow -Check 'ExchangeLicence' -Status 'Warn' -Detail "Mailbox service plan still provisioning: $(& $Describe $Pending)." -Fix $SupportFix
        } else {
            Add-ExoHealthRow -Check 'ExchangeLicence' -Status 'Pass' -Detail "Mailbox service plans provisioned: $((@($Ready.Plan) | Sort-Object -Unique) -join ', ')."
        }
    } catch {
        $Err = Get-ExoHealthError $_
        $Errors.Add("Subscriptions: $Err")
        Add-ExoHealthRow -Check 'ExchangeLicence' -Status 'Warn' -Detail "Could not read the tenant's subscriptions: $Err" -Errored $true
    }

    # Tenant age only softens a failing Get-OrganizationConfig: a tenant created hours ago may still be provisioning.
    $TenantCreated = $null
    try {
        $Org = New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/organization?$select=id,createdDateTime' -tenantid $TenantFilter | Select-Object -First 1
        $TenantCreated = ConvertTo-ExoHealthUtc $Org.createdDateTime
    } catch {
        $Errors.Add("Organization: $(Get-ExoHealthError $_)")
    }

    # --- OrganizationConfig ----------------------------------------------------------------------------------------
    $ExoReachable = $false
    try {
        $OrgConfig = New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-OrganizationConfig' -Select 'Name,Guid,IsDehydrated,IsValid,WhenCreated,AdminDisplayVersion' -ErrorAction Stop | Select-Object -First 1
        if ($null -eq $OrgConfig) { throw 'Get-OrganizationConfig returned nothing' }
        $ExoReachable = $true
        if ($OrgConfig.IsValid -eq $false) {
            Add-ExoHealthRow -Check 'OrganizationConfig' -Status 'Warn' -Detail "Exchange organisation $($OrgConfig.Name) answered but reports IsValid = false." -Fix $SupportFix
        } else {
            Add-ExoHealthRow -Check 'OrganizationConfig' -Status 'Pass' -Detail "Exchange organisation $($OrgConfig.Name) answered (version $($OrgConfig.AdminDisplayVersion))."
        }
        if ($OrgConfig.IsDehydrated -eq $true) {
            Add-ExoHealthRow -Check 'OrganizationCustomization' -Status 'Info' -Detail 'The Exchange organisation is dehydrated (normal for small tenants). Custom role groups and some policy changes need organisation customisation first.' -Fix 'Only if a change asks for it: run Enable-OrganizationCustomization (one time, cannot be undone).'
        }
    } catch {
        $Err = Get-ExoHealthError $_
        $LicenceShaped = (Get-CIPPAlertFailureSeverity -ErrorText $Err) -eq 'Info'
        if ($HasMailboxPlan -eq $false -or ($null -eq $HasMailboxPlan -and $LicenceShaped)) {
            # No mailbox licence and no Exchange organisation is consistent, not a failure.
            $NoExchangeLicence = $true
            Add-ExoHealthRow -Check 'OrganizationConfig' -Status 'Info' -Detail "No Exchange licence: Exchange Online did not answer ($Err)." -Fix 'None needed unless the tenant should have Exchange.'
        } else {
            # Licensed but unreachable is the provisioning failure this check exists for, even when the error text
            # reads like a licence error ("not provisioned").
            $Young = $TenantCreated -and $TenantCreated -gt $Cutoff
            $Errors.Add("Get-OrganizationConfig: $Err")
            Add-ExoHealthRow -Check 'OrganizationConfig' -Status $(if ($Young) { 'Warn' } else { 'Fail' }) -Detail "Exchange Online did not answer Get-OrganizationConfig$(if ($Young) { " (tenant created $([int]($Now - $TenantCreated).TotalHours) hours ago, may still be provisioning)" }): $Err" -Fix $SupportFix -Errored $true
        }
    }

    if (-not $ExoReachable) {
        foreach ($Name in 'RoleGroups', 'ManagementRoles', 'OrgManagementRoles', 'AcceptedDomains', 'LicensedUserMailboxes') {
            Add-ExoHealthRow -Check $Name -Status 'Info' -Detail 'Skipped: Exchange Online did not answer.'
        }
    } else {
        # --- RoleGroups ------------------------------------------------------------------------------------------------
        try {
            # Every one of these existed on aspendora.com (2026-11-01). Names only: with -Select, Roles comes back as one
            # space-joined string, not a list.
            $Expected = @('Organization Management', 'Recipient Management', 'View-Only Organization Management', 'Help Desk',
                'Hygiene Management', 'Compliance Management', 'Discovery Management', 'Records Management',
                'Security Administrator', 'Security Reader')
            $Groups = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-RoleGroup' -Select 'Name' -ErrorAction Stop | ForEach-Object { [string]$_.Name })
            $Missing = @($Expected | Where-Object { $Groups -notcontains $_ })
            if ($Groups.Count -eq 0 -or $Missing -contains 'Organization Management') {
                Add-ExoHealthRow -Check 'RoleGroups' -Status 'Fail' -Detail $(if ($Groups.Count -eq 0) { 'Exchange returned no role groups: RBAC was never created.' } else { "Built-in role groups missing: $($Missing -join ', ')." }) -Fix $SupportFix
            } elseif ($Missing.Count -gt 0) {
                Add-ExoHealthRow -Check 'RoleGroups' -Status 'Warn' -Detail "Built-in role groups missing: $($Missing -join ', ')." -Fix $SupportFix
            } else {
                Add-ExoHealthRow -Check 'RoleGroups' -Status 'Pass' -Detail "All $($Expected.Count) built-in role groups exist ($($Groups.Count) role groups in total)."
            }
        } catch {
            $Err = Get-ExoHealthError $_
            $Errors.Add("Get-RoleGroup: $Err")
            Add-ExoHealthRow -Check 'RoleGroups' -Status 'Warn' -Detail "Could not read role groups: $Err" -Errored $true
        }

        # --- ManagementRoles -------------------------------------------------------------------------------------------
        try {
            # Verified present on 3endt.com 2026-11-01. Mailbox creation needs the first two.
            $CoreRoles = @('Mail Recipient Creation', 'Mail Recipients', 'Organization Configuration', 'Role Management',
                'Remote and Accepted Domains', 'Distribution Groups', 'Reset Password', 'User Options',
                'View-Only Configuration', 'View-Only Recipients')
            $Roles = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-ManagementRole' -Select 'Name' -ErrorAction Stop | ForEach-Object { [string]$_.Name })
            $Missing = @($CoreRoles | Where-Object { $Roles -notcontains $_ })
            if ($Missing.Count -gt 0) {
                Add-ExoHealthRow -Check 'ManagementRoles' -Status 'Fail' -Detail $(if ($Roles.Count -eq 0) { 'Exchange returned no management roles: RBAC was never created.' } else { "Core management roles missing: $($Missing -join ', ')." }) -Fix $SupportFix
            } else {
                Add-ExoHealthRow -Check 'ManagementRoles' -Status 'Pass' -Detail "Core management roles exist ($($Roles.Count) roles in total)."
            }
        } catch {
            $Err = Get-ExoHealthError $_
            $Errors.Add("Get-ManagementRole: $Err")
            Add-ExoHealthRow -Check 'ManagementRoles' -Status 'Warn' -Detail "Could not read management roles: $Err" -Errored $true
        }

        # --- OrgManagementRoles ----------------------------------------------------------------------------------------
        try {
            $Assigned = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-ManagementRoleAssignment' -cmdParams @{ Delegating = $false } -ErrorAction Stop |
                    Where-Object { $_.RoleAssigneeName -eq 'Organization Management' } | ForEach-Object { [string]$_.Role })
            $Definitions = @(New-GraphGetRequest -tenantid $TenantFilter -uri 'https://graph.microsoft.com/beta/roleManagement/exchange/roleDefinitions')
            $RolePath = Join-Path (Join-Path $env:CIPPRootPath 'Config') 'OrganizationManagementRoles.json'
            $Wanted = @(Get-Content -Path $RolePath -Raw -ErrorAction Stop | ConvertFrom-Json)
            $Available = @($Definitions | Where-Object { [string]$_.displayName -in $Wanted } | ForEach-Object { [string]$_.displayName })
            $MissingOrgRoles = @($Available | Where-Object { $Assigned -notcontains $_ } | Sort-Object -Unique)
            # Same threshold as the Tenant Access check: a handful can lag on any tenant, 5+ means RBAC never finished.
            if ($MissingOrgRoles.Count -ge 5) {
                Add-ExoHealthRow -Check 'OrgManagementRoles' -Status 'Fail' -Detail "Organization Management is missing $($MissingOrgRoles.Count) roles: $($MissingOrgRoles -join ', ')." -Fix $RepairFix
            } elseif ($MissingOrgRoles.Count -gt 0) {
                Add-ExoHealthRow -Check 'OrgManagementRoles' -Status 'Warn' -Detail "Organization Management is missing $($MissingOrgRoles.Count) role(s): $($MissingOrgRoles -join ', ')." -Fix $RepairFix
            } else {
                Add-ExoHealthRow -Check 'OrgManagementRoles' -Status 'Pass' -Detail "Organization Management holds every expected role ($($Assigned.Count) assignments)."
            }
        } catch {
            $Err = Get-ExoHealthError $_
            $Errors.Add("Organization Management roles: $Err")
            Add-ExoHealthRow -Check 'OrgManagementRoles' -Status 'Warn' -Detail "Could not compare Organization Management roles: $Err" -Fix 'The comparison needs the RoleManagement.Read.Exchange (or ReadWrite) Graph permission; run a CPV permission refresh if it is missing.' -Errored $true
        }

        # --- AcceptedDomains -------------------------------------------------------------------------------------------
        try {
            $Accepted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($D in @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-AcceptedDomain' -Select 'DomainName,DomainType,Default,InitialDomain' -ErrorAction Stop)) {
                if ($D.DomainName) { [void]$Accepted.Add([string]$D.DomainName) }
            }
            $Domains = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/domains?$select=id,isVerified,isInitial,supportedServices' -tenantid $TenantFilter)
            # Domains without the Email service (e.g. *.mail.onmicrosoft.com, third-party routing domains) are not expected.
            $EmailDomains = @($Domains | Where-Object { $_.isVerified -eq $true -and @($_.supportedServices) -contains 'Email' })
            $MissingDomains = @($EmailDomains | Where-Object { -not $Accepted.Contains([string]$_.id) } | ForEach-Object { ([string]$_.id).ToLowerInvariant() } | Sort-Object -Unique)
            $InitialMissing = @($EmailDomains | Where-Object { $_.isInitial -eq $true -and -not $Accepted.Contains([string]$_.id) }).Count -gt 0
            if ($Accepted.Count -eq 0 -or $InitialMissing) {
                Add-ExoHealthRow -Check 'AcceptedDomains' -Status 'Fail' -Detail $(if ($Accepted.Count -eq 0) { 'Exchange has no accepted domains.' } else { "The initial onmicrosoft.com domain is not an accepted domain. Missing: $($MissingDomains -join ', ')." }) -Fix $SupportFix
            } elseif ($MissingDomains.Count -gt 0) {
                Add-ExoHealthRow -Check 'AcceptedDomains' -Status 'Warn' -Detail "Verified for email in Entra but not accepted in Exchange: $($MissingDomains -join ', ')." -Fix 'Domains sync to Exchange within an hour of verification. If one is still missing, re-save it in the Microsoft 365 admin center (Settings > Domains) with the Exchange service selected; if that fails, open a Microsoft support case.'
            } else {
                Add-ExoHealthRow -Check 'AcceptedDomains' -Status 'Pass' -Detail "All $($EmailDomains.Count) email domains are accepted domains ($($Accepted.Count) accepted in total)."
            }
        } catch {
            $Err = Get-ExoHealthError $_
            $Errors.Add("Accepted domains: $Err")
            Add-ExoHealthRow -Check 'AcceptedDomains' -Status 'Warn' -Detail "Could not compare accepted domains: $Err" -Errored $true
        }

        # --- LicensedUserMailboxes -------------------------------------------------------------------------------------
        if ($HasMailboxPlan -eq $false) {
            Add-ExoHealthRow -Check 'LicensedUserMailboxes' -Status 'Info' -Detail 'Skipped: no mailbox licence in the tenant.'
        } else {
            try {
                $Users = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,userType,createdDateTime,assignedPlans&$top=999' -tenantid $TenantFilter)
                $Eligible = @(foreach ($U in $Users) {
                        if ([string]$U.userType -eq 'Guest') { continue }
                        $MailboxPlans = @($U.assignedPlans | Where-Object { [string]$_.capabilityStatus -eq 'Enabled' -and $MailboxPlanIds.Contains([string]$_.servicePlanId) })
                        if ($MailboxPlans.Count -eq 0) { continue }
                        # Provisioning starts at the later of account creation and the first mailbox plan assignment.
                        $PlanSince = @($MailboxPlans | ForEach-Object { ConvertTo-ExoHealthUtc $_.assignedDateTime } | Where-Object { $_ } | Sort-Object | Select-Object -First 1)
                        $Created = ConvertTo-ExoHealthUtc $U.createdDateTime
                        $Since = @(@($PlanSince) + @($Created) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1)
                        $SinceValue = if ($Since.Count -gt 0) { $Since[0] } else { $null }
                        if ($SinceValue -and $SinceValue -gt $Cutoff) { continue }
                        [pscustomobject]@{ id = [string]$U.id; userPrincipalName = [string]$U.userPrincipalName; displayName = [string]$U.displayName; licensedSince = if ($SinceValue) { $SinceValue.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }
                    })
                $RecipientTypes = @{}
                foreach ($Rcpt in @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-Recipient' -cmdParams @{ ResultSize = 'Unlimited' } -Select 'ExternalDirectoryObjectId,RecipientTypeDetails' -ErrorAction Stop)) {
                    if ($Rcpt.ExternalDirectoryObjectId) { $RecipientTypes[([string]$Rcpt.ExternalDirectoryObjectId).ToLowerInvariant()] = [string]$Rcpt.RecipientTypeDetails }
                }
                $UsersWithoutMailbox = @($Eligible | Where-Object { -not $RecipientTypes.ContainsKey($_.id.ToLowerInvariant()) })
                # A licensed MailUser is a hybrid user whose mailbox is still on-premises (or a stuck migration): context, not a failure.
                $MailUsers = @($Eligible | Where-Object { $RecipientTypes[$_.id.ToLowerInvariant()] -eq 'MailUser' })
                $HybridNote = if ($MailUsers.Count -gt 0) { " $($MailUsers.Count) licensed user(s) are mail users (mailbox on-premises or mid-migration)." } else { '' }
                $Fix = 'Mailboxes normally appear within minutes of licensing. Check the user in Microsoft 365 admin center for a licence or provisioning error (duplicate proxy address, ExchangeGuid conflict, or a hybrid user missing msExchMailboxGuid). Remove and re-add the licence once the cause is fixed. If no licensed user has a mailbox, the Exchange organisation itself did not provision: see the other checks.'
                if ($Eligible.Count -eq 0) {
                    Add-ExoHealthRow -Check 'LicensedUserMailboxes' -Status 'Pass' -Detail "No member has held a mailbox licence for more than $GraceHours hours yet."
                } elseif ($UsersWithoutMailbox.Count -eq $Eligible.Count) {
                    Add-ExoHealthRow -Check 'LicensedUserMailboxes' -Status 'Fail' -Detail "None of the $($Eligible.Count) users licensed for a mailbox for more than $GraceHours hours has one: mailbox provisioning is failing for the whole tenant." -Fix $Fix
                } elseif ($UsersWithoutMailbox.Count -gt 0) {
                    Add-ExoHealthRow -Check 'LicensedUserMailboxes' -Status 'Warn' -Detail "$($UsersWithoutMailbox.Count) of $($Eligible.Count) users licensed for a mailbox for more than $GraceHours hours have no Exchange recipient: $((@($UsersWithoutMailbox | Select-Object -First 10 | ForEach-Object { $_.userPrincipalName })) -join ', ')$(if ($UsersWithoutMailbox.Count -gt 10) { ', ...' }).$HybridNote" -Fix $Fix
                } else {
                    Add-ExoHealthRow -Check 'LicensedUserMailboxes' -Status 'Pass' -Detail "All $($Eligible.Count) users licensed for a mailbox for more than $GraceHours hours have an Exchange recipient.$HybridNote"
                }
            } catch {
                $Err = Get-ExoHealthError $_
                $Errors.Add("Licensed user mailboxes: $Err")
                Add-ExoHealthRow -Check 'LicensedUserMailboxes' -Status 'Warn' -Detail "Could not compare licensed users with mailboxes: $Err" -Errored $true
            }
        }
    }

    $Rows = @($Checks)
    $Count = { param($S) @($Rows | Where-Object Status -EQ $S).Count }
    $Fail = & $Count 'Fail'
    $Warn = & $Count 'Warn'
    $Overall = if ($Fail -gt 0) { 'Fail' } elseif ($Warn -gt 0) { 'Warn' } elseif ($NoExchangeLicence) { 'Info' } else { 'Pass' }
    $Summary = [ordered]@{
        Overall           = $Overall
        Pass              = & $Count 'Pass'
        Warn              = $Warn
        Fail              = $Fail
        Info              = & $Count 'Info'
        NoExchangeLicence = $NoExchangeLicence
        RepairSuggested   = $MissingOrgRoles.Count -gt 0
    }

    return [pscustomobject]@{
        Tenant                    = $TenantFilter
        CheckedAt                 = $Now.ToString('yyyy-MM-ddTHH:mm:ssZ')
        GraceHours                = $GraceHours
        Summary                   = $Summary
        Checks                    = $Rows
        MissingDomains            = @($MissingDomains)
        UsersWithoutMailbox       = @($UsersWithoutMailbox)
        LicensedMailUsers         = @($MailUsers)
        MissingOrgManagementRoles = @($MissingOrgRoles)
        Errors                    = @($Errors)
    }
}
