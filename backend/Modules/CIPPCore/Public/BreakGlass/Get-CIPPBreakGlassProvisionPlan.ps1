function Get-CIPPBreakGlassProvisionPlan {
    <#
    .SYNOPSIS
        Works out exactly what break-glass provisioning would do in one tenant, without changing anything.
    .DESCRIPTION
        Read-only. The plan names the accounts to create (exact UPNs), whether the exclusion group exists, and
        every Conditional Access policy that would be edited. Lacy approves this plan, and the executor refuses
        to run anything the fresh plan no longer matches.

        Gates, in order (Status = Blocked or NotNeeded and nothing else is read):
          - the tenant is known to CIPP and not on CIPP's exclusion list;
          - the tenant is a Managed Client (Test-CIPPTenantManaged, synced daily from ConnectWise company types;
            it fails closed, so 'Unknown' blocks);
          - fewer than 2 break-glass accounts are registered (2 is the standard, Hudu 737).
        Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [int]$Target = 2,
        [string]$GroupName = 'CA Exclusion - Break-glass accounts'
    )

    $Plan = [ordered]@{
        TenantId = $null; Tenant = $TenantFilter; DisplayName = $null; Status = 'Blocked'; Reasons = [System.Collections.Generic.List[string]]::new()
        Managed = $null; Registered = @(); AccountsToCreate = @(); InitialDomain = $null
        GroupId = $null; GroupAction = $null; PolicyEdits = @(); PoliciesAlreadyExcluded = @()
        Warnings = [System.Collections.Generic.List[string]]::new(); GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $Done = { [pscustomobject]$Plan }

    $Tenant = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1
    if (-not $Tenant.customerId) { $Plan.Reasons.Add('Tenant not found in CIPP.'); return (& $Done) }
    $Plan.TenantId = ([string]$Tenant.customerId).ToLower()
    $Plan.Tenant = $Tenant.defaultDomainName
    $Plan.DisplayName = $Tenant.displayName
    if ($Plan.TenantId -eq ([string]$env:TenantID).ToLower()) { $Plan.Reasons.Add('Partner tenant: break-glass is managed by hand.'); return (& $Done) }

    $Skipped = @(Get-Tenants -SkipList | Where-Object { ([string]$_.customerId).ToLower() -eq $Plan.TenantId })
    if ($Skipped.Count -gt 0) { $Plan.Reasons.Add('Tenant is on the CIPP exclusion list.'); return (& $Done) }

    $Managed = Test-CIPPTenantManaged -TenantFilter $Plan.Tenant
    $Plan.Managed = $Managed.Status
    if (-not $Managed.IsManaged) {
        $Plan.Reasons.Add("Not a Managed Client (status: $($Managed.Status)$(if ($Managed.Error) { "; $($Managed.Error)" })). Break-glass accounts are only created for Managed Client tenants.")
        return (& $Done)
    }

    $Registered = @(Get-CIPPBreakGlassAccounts -TenantFilter $Plan.TenantId)
    $Plan.Registered = @($Registered | ForEach-Object { [string]$_.UserPrincipalName })
    $Needed = $Target - $Registered.Count
    if ($Needed -le 0) { $Plan.Status = 'NotNeeded'; $Plan.Reasons.Add("$($Registered.Count) break-glass account(s) already registered."); return (& $Done) }

    try {
        $Domains = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/domains?$select=id,isInitial' -tenantid $Plan.Tenant -ErrorAction Stop)
        $Plan.InitialDomain = ($Domains | Where-Object { $_.isInitial -eq $true } | Select-Object -First 1).id
        if (-not $Plan.InitialDomain) { throw 'no initial domain returned' }

        $Upns = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users?`$select=userPrincipalName&`$filter=startswith(userPrincipalName,'bg-')" -tenantid $Plan.Tenant -ErrorAction Stop | ForEach-Object userPrincipalName)
        $Plan.AccountsToCreate = @(New-CIPPBreakGlassAccountName -InitialDomain $Plan.InitialDomain -Count $Needed -Existing $Upns)

        $Escaped = $GroupName -replace "'", "''"
        $Groups = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,isAssignableToRole,securityEnabled,mailEnabled&`$filter=displayName eq '$Escaped'" -tenantid $Plan.Tenant -ErrorAction Stop)
        if ($Groups.Count -gt 1) { $Plan.Reasons.Add("$($Groups.Count) groups are named '$GroupName'. Resolve that by hand first."); return (& $Done) }
        if ($Groups.Count -eq 1) {
            if ($Groups[0].isAssignableToRole -ne $true -or $Groups[0].securityEnabled -ne $true) {
                $Plan.Reasons.Add("A group named '$GroupName' exists but is not a role-assignable security group ($($Groups[0].id)). Fix or rename it by hand first.")
                return (& $Done)
            }
            $Plan.GroupId = $Groups[0].id; $Plan.GroupAction = 'UseExisting'
        } else { $Plan.GroupAction = 'Create' }

        $Policies = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies' -tenantid $Plan.Tenant -ErrorAction Stop)
        $Edits = [System.Collections.Generic.List[object]]::new(); $Already = [System.Collections.Generic.List[string]]::new()
        foreach ($P in $Policies) {
            if ($Plan.GroupId -and @($P.conditions.users.excludeGroups) -contains $Plan.GroupId) { $Already.Add($P.displayName); continue }
            $Edits.Add([pscustomobject]@{ Id = $P.id; DisplayName = $P.displayName; State = $P.state })
        }
        $Plan.PolicyEdits = @($Edits); $Plan.PoliciesAlreadyExcluded = @($Already)

        try {
            $PlanSummary = Get-CIPPCAPlanSummary -Plans @(Get-CIPPConditionalAccessPlans -TenantFilter $Plan.Tenant)
            if ($PlanSummary.PlanCount -gt 0) { $Plan.Warnings.Add("$($PlanSummary.Warning) Plan rules are not edited; exclude the group from each plan by hand.") }
        } catch { $Plan.Warnings.Add('Could not read Conditional Access plans; check for plan rules by hand.') }

        foreach ($Method in 'Fido2', 'TemporaryAccessPass') {
            try {
                $Conf = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$Method" -tenantid $Plan.Tenant -ErrorAction Stop
                if ($Conf.state -ne 'enabled') { $Plan.Warnings.Add("$Method is disabled in the tenant's authentication methods policy, so the keys-pending step cannot be finished until it is enabled.") }
            } catch { $Plan.Warnings.Add("Could not read the $Method authentication method policy.") }
        }
    } catch {
        $Plan.Reasons.Add("Could not read the tenant: $($_.Exception.Message)")
        return (& $Done)
    }

    $Plan.Status = 'Ready'
    return (& $Done)
}
