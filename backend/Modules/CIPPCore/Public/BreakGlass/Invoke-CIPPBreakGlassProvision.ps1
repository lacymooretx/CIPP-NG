function Invoke-CIPPBreakGlassProvision {
    <#
    .SYNOPSIS
        Carries out an APPROVED break-glass plan in one tenant: accounts, Global Admin, exclusion group, CA
        exclusions, registry, ControlR/Keeper hand-off, then posture and an alert with a CW ticket.
    .DESCRIPTION
        Only runs on an approved plan, and only if a fresh plan still matches it (still Ready, same accounts to
        create). Every write is read back. Each CA policy is snapshotted before and after in table
        BreakGlassCASnapshots (PartitionKey = run id) for rollback.

        Stops at the first failure that would leave an unsafe state: no Global Admin without the account
        existing, no CA edit without the group holding the accounts. A CA policy that cannot be edited (for
        example Graph 1039 on P2 risk policies) is reported, not fatal.

        The initial password is random, set once and discarded. CIPP never stores, logs or returns it. ControlR's
        break-glass rotate route then sets the real password and writes Keeper (and Hudu, its normal behaviour).
        If that route is unavailable the account is left with an unknown password and the alert says
        "Keeper pending", which is safe: nobody can use the account until ControlR rotates it.

        FIDO2 cannot be automated. The account ends "created, keys pending" and the CW ticket tells a tech to
        issue a Temporary Access Pass in CIPP when they have the keys in hand, then register two keys or passkeys.
        Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        # The approved plan (from table BreakGlassProvision, PartitionKey 'Plan').
        [Parameter(Mandatory)]$ApprovedPlan,
        [string]$ApprovedBy = 'unknown',
        $Headers
    )

    $APIName = 'BreakGlassProvision'
    $GA = '62e90394-69f5-4237-9190-012177145e10'
    $RunId = (New-Guid).Guid
    $Steps = [System.Collections.Generic.List[object]]::new()
    $Step = { param($Name, $Ok, $Detail) $Steps.Add([pscustomobject]@{ Step = $Name; Ok = [bool]$Ok; Detail = [string]$Detail }) }
    $Result = [ordered]@{ RunId = $RunId; Tenant = $TenantFilter; Status = 'Failed'; ApprovedBy = $ApprovedBy; Accounts = @(); GroupId = $null; PolicyResults = @(); Keeper = @(); Posture = $null; Steps = $Steps }

    $Settings = Get-CIPPBreakGlassProvisionSettings
    if (-not $Settings.Enabled) { & $Step 'Kill switch' $false 'Break-glass provisioning is switched off (BreakGlassProvision settings).'; return [pscustomobject]$Result }

    $Fresh = Get-CIPPBreakGlassProvisionPlan -TenantFilter $TenantFilter
    $ApprovedUpns = @($ApprovedPlan.AccountsToCreate)
    if ($Fresh.Status -ne 'Ready') { & $Step 'Re-plan' $false "The tenant is no longer Ready: $($Fresh.Status). $($Fresh.Reasons -join ' ')"; return [pscustomobject]$Result }
    if ($Fresh.AccountsToCreate.Count -ne $ApprovedUpns.Count -or $Fresh.GroupAction -ne $ApprovedPlan.GroupAction -or ($Fresh.GroupId -and $Fresh.GroupId -ne $ApprovedPlan.GroupId)) {
        & $Step 'Re-plan' $false 'The tenant changed since the plan was approved (account count or group). Generate and approve a new plan.'
        return [pscustomobject]$Result
    }
    & $Step 'Re-plan' $true "Still Ready; $($Fresh.PolicyEdits.Count) CA policies to edit."
    $Tenant = $Fresh.Tenant
    $Result.Tenant = $Tenant

    if (-not $PSCmdlet.ShouldProcess($Tenant, "Create $($ApprovedUpns.Count) break-glass account(s)")) { return [pscustomobject]$Result }

    # 1. Accounts.
    $Created = [System.Collections.Generic.List[object]]::new()
    $i = $Fresh.Registered.Count
    foreach ($Upn in $ApprovedUpns) {
        $i++
        $Nick = ($Upn -split '@')[0]
        $Body = @{
            accountEnabled = $true; displayName = "Aspendora Break-Glass $i"; mailNickname = $Nick; userPrincipalName = $Upn
            passwordPolicies = 'DisablePasswordExpiration'
            passwordProfile = @{ forceChangePasswordNextSignIn = $false; password = (New-CIPPBreakGlassPassword) }
        } | ConvertTo-Json -Compress
        try {
            $User = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/v1.0/users' -tenantid $Tenant -type POST -body $Body -ErrorAction Stop
        } catch {
            # The message only: the request body holds the password.
            & $Step "Create $Upn" $false (Get-NormalizedError -Message $_.Exception.Message)
            break
        } finally { $Body = $null }
        $Check = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($User.id)?`$select=id,userPrincipalName,accountEnabled,passwordPolicies,onPremisesSyncEnabled,assignedLicenses" -tenantid $Tenant
        $Ok = $Check.userPrincipalName -eq $Upn -and $Check.accountEnabled -eq $true -and [string]$Check.passwordPolicies -match 'DisablePasswordExpiration' -and @($Check.assignedLicenses).Count -eq 0
        & $Step "Create $Upn" $Ok "id $($User.id)"
        if (-not $Ok) { break }
        $Created.Add([pscustomobject]@{ Id = $User.id; UserPrincipalName = $Upn; DisplayName = "Aspendora Break-Glass $i" })
    }
    $Result.Accounts = @($Created)
    if ($Created.Count -ne $ApprovedUpns.Count) { return (Complete-CIPPBreakGlassRun -Result $Result -Tenant $Tenant -APIName $APIName) }

    # 2. Permanent active Global Administrator.
    foreach ($A in $Created) {
        try {
            $Assign = @{ principalId = $A.Id; roleDefinitionId = $GA; directoryScopeId = '/' } | ConvertTo-Json -Compress
            $null = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments' -tenantid $Tenant -type POST -body $Assign -ErrorAction Stop
            $Read = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($A.Id)' and roleDefinitionId eq '$GA'" -tenantid $Tenant)
            & $Step "Global Admin $($A.UserPrincipalName)" ($Read.Count -ge 1) "$($Read.Count) assignment(s) read back"
            if ($Read.Count -lt 1) { return (Complete-CIPPBreakGlassRun -Result $Result -Tenant $Tenant -APIName $APIName) }
        } catch {
            & $Step "Global Admin $($A.UserPrincipalName)" $false (Get-NormalizedError -Message $_.Exception.Message)
            return (Complete-CIPPBreakGlassRun -Result $Result -Tenant $Tenant -APIName $APIName)
        }
    }

    # 3. Role-assignable exclusion group, holding only the break-glass accounts.
    try {
        $GroupId = $Fresh.GroupId
        if ($Fresh.GroupAction -eq 'Create') {
            $GroupBody = @{
                displayName = 'CA Exclusion - Break-glass accounts'; mailEnabled = $false; mailNickname = 'ca-exclusion-breakglass'
                securityEnabled = $true; isAssignableToRole = $true
                description = 'Aspendora emergency-access accounts only. Excluded from every Conditional Access policy. Do not add anything else (Hudu 737).'
            } | ConvertTo-Json -Compress
            $GroupId = (New-GraphPOSTRequest -uri 'https://graph.microsoft.com/v1.0/groups' -tenantid $Tenant -type POST -body $GroupBody -ErrorAction Stop).id
        }
        foreach ($A in $Created) {
            $Ref = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($A.Id)" } | ConvertTo-Json -Compress
            $null = New-GraphPOSTRequest -uri "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref" -tenantid $Tenant -type POST -body $Ref -ErrorAction Stop
        }
        $Members = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id" -tenantid $Tenant | ForEach-Object id)
        $Missing = @($Created | Where-Object { $_.Id -notin $Members })
        & $Step 'Exclusion group' ($Missing.Count -eq 0) "$GroupId ($($Fresh.GroupAction)); $($Members.Count) member(s)"
        $Result.GroupId = $GroupId
        if ($Missing.Count -gt 0) { return (Complete-CIPPBreakGlassRun -Result $Result -Tenant $Tenant -APIName $APIName) }
    } catch {
        & $Step 'Exclusion group' $false (Get-NormalizedError -Message $_.Exception.Message)
        return (Complete-CIPPBreakGlassRun -Result $Result -Tenant $Tenant -APIName $APIName)
    }

    # 4. Exclude the group from every CA policy, with before/after snapshots.
    $SnapTable = Get-CIPPTable -tablename 'BreakGlassCASnapshots'
    $PolicyResults = [System.Collections.Generic.List[object]]::new()
    foreach ($P in @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies' -tenantid $Tenant)) {
        $Patch = New-CIPPBreakGlassCAPatch -Policy $P -GroupId $GroupId
        if ($null -eq $Patch) { $PolicyResults.Add([pscustomobject]@{ Policy = $P.displayName; Id = $P.id; Result = 'AlreadyExcluded' }); continue }
        Add-CIPPAzDataTableEntity @SnapTable -Entity @{ PartitionKey = $RunId; RowKey = "$($P.id)|before"; Tenant = $Tenant; Json = (ConvertTo-Json -InputObject $P -Depth 20 -Compress) } -Force
        try {
            $null = New-GraphPOSTRequest -uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($P.id)" -tenantid $Tenant -type PATCH -body (ConvertTo-Json -InputObject $Patch -Depth 10 -Compress) -ErrorAction Stop
            $After = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($P.id)" -tenantid $Tenant
            Add-CIPPAzDataTableEntity @SnapTable -Entity @{ PartitionKey = $RunId; RowKey = "$($P.id)|after"; Tenant = $Tenant; Json = (ConvertTo-Json -InputObject $After -Depth 20 -Compress) } -Force
            $Check = Test-CIPPBreakGlassCAReadback -Before $P -After $After -GroupId $GroupId
            $PolicyResults.Add([pscustomobject]@{ Policy = $P.displayName; Id = $P.id; Result = $(if ($Check.Ok) { 'Excluded' } else { "ReadbackMismatch: $($Check.Problems -join '; ')" }) })
        } catch {
            $PolicyResults.Add([pscustomobject]@{ Policy = $P.displayName; Id = $P.id; Result = "Failed: $(Get-NormalizedError -Message $_.Exception.Message)" })
        }
    }
    $Result.PolicyResults = @($PolicyResults)
    $Bad = @($PolicyResults | Where-Object { $_.Result -notin 'Excluded', 'AlreadyExcluded' })
    & $Step 'CA exclusions' ($Bad.Count -eq 0) "$(@($PolicyResults | Where-Object Result -EQ 'Excluded').Count) edited, $(@($PolicyResults | Where-Object Result -EQ 'AlreadyExcluded').Count) already excluded, $($Bad.Count) problem(s). Snapshots: BreakGlassCASnapshots/$RunId"

    # 5. Register, so the activity, exclusion-change and posture alerts watch the accounts from now on.
    $Registry = Get-CIPPTable -tablename 'BreakGlassAccounts'
    foreach ($A in $Created) {
        Add-CIPPAzDataTableEntity @Registry -Entity @{
            PartitionKey = $Fresh.TenantId; RowKey = [string]$A.Id; UserPrincipalName = $A.UserPrincipalName; DisplayName = $A.DisplayName
            Note = "Provisioned by CIPP run $RunId, approved by $ApprovedBy. Keys pending."; AddedBy = 'CIPP break-glass provisioning'
            AddedUtc = (Get-Date).ToUniversalTime().ToString('o'); ProvisionRunId = $RunId; KeysPending = $true
        } -Force
    }
    $Reg = @(Get-CIPPBreakGlassAccounts -TenantFilter $Fresh.TenantId | ForEach-Object RowKey)
    & $Step 'Registry' (@($Created | Where-Object { $_.Id -notin $Reg }).Count -eq 0) "$($Reg.Count) registered"

    # 6. ControlR sets the real password and writes Keeper. CIPP sees only the record pointer.
    $Keeper = [System.Collections.Generic.List[object]]::new()
    foreach ($A in $Created) {
        # Contract: ControlR f46de0ba8 (Hudu 841). Synchronous; the NPM proxy drops at ~90 s, so on a timeout check the
        # account in ControlR before calling again (a re-call rotates again, which is harmless).
        $Hand = Invoke-CippControlRIntegrationRequest -Method POST -Path 'break-glass/rotate' -TimeoutSec 90 -Body @{ entraTenantId = $Fresh.TenantId; entraObjectId = $A.Id; upn = $A.UserPrincipalName }
        $Uid = if ($Hand.Data.status -eq 'Success') { [string]$Hand.Data.keeperRecordUid } else { $null }
        $Keeper.Add([pscustomobject]@{ UserPrincipalName = $A.UserPrincipalName; Status = $(if ($Uid) { 'Rotated' } else { "Keeper pending: $($Hand.Message)" }); KeeperRecordUid = $Uid; HuduPasswordId = $Hand.Data.huduPasswordId; RotatedAt = $Hand.Data.rotatedAt })
        if ($Uid) {
            $Row = Get-CIPPAzDataTableEntity @Registry -Filter "PartitionKey eq '$($Fresh.TenantId)' and RowKey eq '$($A.Id)'"
            $Row | Add-Member -NotePropertyName KeeperRecordUid -NotePropertyValue $Uid -Force
            Add-CIPPAzDataTableEntity @Registry -Entity $Row -Force
        }
    }
    $Result.Keeper = @($Keeper)
    & $Step 'Keeper (ControlR)' (@($Keeper | Where-Object { -not $_.KeeperRecordUid }).Count -eq 0) (($Keeper | ForEach-Object { "$($_.UserPrincipalName): $($_.Status)" }) -join '; ')

    # 7. Posture, for the record. "No FIDO2" stays open until the keys are registered.
    try {
        $Posture = Get-CIPPBreakGlassPosture -TenantFilter $Tenant
        $Result.Posture = @($Posture.Findings | Select-Object Severity, Check, Account, Message)
    } catch { & $Step 'Posture' $false (Get-NormalizedError -Message $_.Exception.Message) }

    $Result.Status = if (@($Steps | Where-Object { -not $_.Ok }).Count -eq 0) { 'Succeeded' } else { 'CompletedWithProblems' }
    return (Complete-CIPPBreakGlassRun -Result $Result -Tenant $Tenant -APIName $APIName)
}
