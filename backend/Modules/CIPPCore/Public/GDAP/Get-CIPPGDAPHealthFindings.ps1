function Get-CIPPGDAPHealthFindings {
    <#
    .SYNOPSIS
        Turns GDAP relationships, access assignments, tenant probes and SAM state into health findings.
    .DESCRIPTION
        Pure evaluation with no Graph or table calls, so every rule can be tested offline.
        Invoke-CIPPGDAPHealthCheck collects the inputs and decides which findings to alert on.

        Each finding has a stable Key. A Key changes only when the situation changes, for example when
        an expiring relationship crosses the next threshold (30 -> 14 -> 7 -> expired). That keeps the
        alerting to one message per real change. Findings with Realert = $true are repeated every few
        days while they persist, because they mean access is broken now.
        Aspendora fork addition (Vikunja CIPP-2).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # Graph delegatedAdminRelationships objects, any status.
        [object[]]$Relationships = @(),
        # Hashtable: relationship id -> active accessAssignments for that relationship.
        # A relationship id with no key means the assignments were not read, so no assignment rule runs for it.
        [hashtable]$AccessAssignments = @{},
        # CIPP tenant list rows (customerId, defaultDomainName, displayName, delegatedPrivilegeStatus).
        [object[]]$Tenants = @(),
        # Hashtable: customerId -> error text for tenants whose Graph probe failed.
        [hashtable]$TenantProbeErrors = @{},
        # @{ Ready = bool; Message = string; CredentialType = 'Secret'|'Certificate'; CredentialExpires = datetime }
        $SamStatus,
        # Previous run: @{ ActiveRelationshipIds = string[]; AssignmentIds = @{ relId = string[] } }. $null on the first run.
        $Previous,
        [string]$PartnerTenantId = $env:TenantID,
        [datetime]$Now = (Get-Date).ToUniversalTime(),
        [int[]]$Thresholds = @(30, 14, 7),
        # Days past the end date before an auto-extending relationship counts as overdue.
        [int]$AutoExtendGraceDays = 1,
        # A SAM credential this close to expiry means the weekly rotation (which fires at 30 days) has failed.
        [int]$SamCredentialWarnDays = 14,
        # The relationship list could not be read: skip the coverage rule instead of flagging every tenant.
        [switch]$RelationshipsUnavailable
    )

    $GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'
    $Thresholds = @($Thresholds | Sort-Object -Descending)
    $Findings = [System.Collections.Generic.List[object]]::new()

    $ManagedTenants = @{}
    foreach ($Tenant in $Tenants) {
        if (-not $Tenant.customerId) { continue }
        if ($Tenant.delegatedPrivilegeStatus -eq 'directTenant') { continue }
        if ($PartnerTenantId -and $Tenant.customerId -eq $PartnerTenantId) { continue }
        $ManagedTenants[[string]$Tenant.customerId] = $Tenant
    }

    $AddFinding = {
        param($Key, $Category, $Severity, $Message, $Relationship, $TenantId, $TenantName, [bool]$Realert, $Extra)
        $Finding = [ordered]@{
            Key                = $Key
            Category           = $Category
            Severity           = $Severity
            Message            = $Message
            TenantId           = [string]$TenantId
            Tenant             = [string]$TenantName
            RelationshipId     = [string]$Relationship.id
            Relationship       = [string]$Relationship.displayName
            Status             = [string]$Relationship.status
            EndDateTime        = $Relationship.endDateTime
            AutoExtendDuration = [string]$Relationship.autoExtendDuration
            Realert            = $Realert
        }
        if ($Extra) { foreach ($Name in $Extra.Keys) { $Finding[$Name] = $Extra[$Name] } }
        $Findings.Add([pscustomobject]$Finding)
    }

    $ToUtc = {
        param($Value)
        if (-not $Value) { return $null }
        try { return ([datetimeoffset]$Value).UtcDateTime } catch { return $null }
    }

    $ByCustomer = @{}
    foreach ($Relationship in $Relationships) {
        $CustomerId = [string]$Relationship.customer.tenantId
        if (-not $CustomerId) { continue }
        if (-not $ByCustomer.ContainsKey($CustomerId)) { $ByCustomer[$CustomerId] = [System.Collections.Generic.List[object]]::new() }
        $ByCustomer[$CustomerId].Add($Relationship)
    }

    foreach ($Relationship in $Relationships) {
        $CustomerId = [string]$Relationship.customer.tenantId
        $Managed = $ManagedTenants.ContainsKey($CustomerId)
        $TenantName = if ($Managed) { $ManagedTenants[$CustomerId].displayName } elseif ($Relationship.customer.displayName) { $Relationship.customer.displayName } else { 'a customer not yet identified' }
        $TenantLabel = "$TenantName$(if (-not $Managed) { ' (not managed in CIPP)' })"
        $RelLabel = "'$($Relationship.displayName)' for $TenantLabel"

        if ($Relationship.status -in @('created', 'approvalPending')) {
            $Created = & $ToUtc $Relationship.createdDateTime
            $Age = if ($Created) { " (created $($Created.ToString('yyyy-MM-dd')), $([math]::Floor(($Now - $Created).TotalDays)) day(s) ago)" } else { '' }
            & $AddFinding "Pending|$($Relationship.id)" 'Pending' 'Info' "GDAP relationship $RelLabel is still $($Relationship.status)$Age and grants no access until the customer approves it. Resend or delete the invite." $Relationship $CustomerId $TenantName $false
            continue
        }
        if ($Relationship.status -ne 'active') { continue }

        $End = & $ToUtc $Relationship.endDateTime
        if (-not $End) { continue }
        $DaysLeft = [math]::Floor(($End - $Now).TotalDays)
        $HasGlobalAdmin = $GlobalAdminRoleId -in @($Relationship.accessDetails.unifiedRoles.roleDefinitionId)
        $AutoExtends = $Relationship.autoExtendDuration -and $Relationship.autoExtendDuration -ne 'PT0S' -and -not $HasGlobalAdmin

        # Is the customer still reachable through another active relationship that outlives this one?
        $Others = @($ByCustomer[$CustomerId] | Where-Object { $_.id -ne $Relationship.id -and $_.status -eq 'active' })
        $Covered = [bool]($Others | Where-Object {
                $OtherEnd = & $ToUtc $_.endDateTime
                $OtherGA = $GlobalAdminRoleId -in @($_.accessDetails.unifiedRoles.roleDefinitionId)
                ($_.autoExtendDuration -and $_.autoExtendDuration -ne 'PT0S' -and -not $OtherGA -and $OtherEnd -gt $Now) -or ($OtherEnd -gt $End)
            })
        $CoverNote = if ($Covered) { ' Another active relationship still covers this customer; check that it carries the roles you need.' } else { " It is this customer's only lasting relationship, so access to the customer depends on it." }

        if ($AutoExtends) {
            if ($End -lt $Now.AddDays(-$AutoExtendGraceDays)) {
                $Severity = if ($Managed -and -not $Covered) { 'Error' } else { 'Warning' }
                & $AddFinding "AutoExtendOverdue|$($Relationship.id)" 'AutoExtendOverdue' $Severity "GDAP relationship $RelLabel is set to auto-extend ($($Relationship.autoExtendDuration)) but its end date $($End.ToString('yyyy-MM-dd')) passed $([math]::Floor(($Now - $End).TotalDays)) day(s) ago and Microsoft has not extended it. Check it in Partner Center.$CoverNote" $Relationship $CustomerId $TenantName $true @{ DaysLeft = $DaysLeft; Managed = $Managed; Covered = $Covered }
            }
        } else {
            $Bucket = if ($DaysLeft -lt 0) { 'expired' } else { $Thresholds | Where-Object { $DaysLeft -le $_ } | Select-Object -Last 1 }
            if ($Bucket) {
                $Why = if ($HasGlobalAdmin) { 'It holds Global Administrator, so Microsoft will not auto-extend it; replace it with a least-privilege relationship.' } else { 'Auto-extend is off. Turn it on (Tenant > GDAP > Relationships > Enable auto-extend, or ExecAutoExtendGDAP).' }
                $When = if ($Bucket -eq 'expired') { "reached its end date $($End.ToString('yyyy-MM-dd'))" } else { "expires on $($End.ToString('yyyy-MM-dd')) ($DaysLeft day(s))" }
                $Severity = if (($Bucket -eq 'expired' -or $DaysLeft -le 7) -and $Managed -and -not $Covered) { 'Error' } else { 'Warning' }
                & $AddFinding "Expiring|$($Relationship.id)|$Bucket" 'Expiring' $Severity "GDAP relationship $RelLabel $When. $Why$CoverNote" $Relationship $CustomerId $TenantName $false @{ DaysLeft = $DaysLeft; Threshold = [string]$Bucket; AutoExtendEligible = (-not $HasGlobalAdmin); Managed = $Managed; Covered = $Covered }
            }
        }

        # Access assignments that were there last run and are gone now.
        $RelId = [string]$Relationship.id
        if ($Previous -and $Previous.AssignmentIds -and $Previous.AssignmentIds.ContainsKey($RelId) -and $AccessAssignments.ContainsKey($RelId)) {
            $NowIds = @($AccessAssignments[$RelId] | ForEach-Object { [string]$_.id })
            foreach ($GoneId in @($Previous.AssignmentIds[$RelId] | Where-Object { $_ -notin $NowIds })) {
                & $AddFinding "AssignmentRemoved|$RelId|$GoneId" 'AssignmentRemoved' ($Managed ? 'Error' : 'Warning') "An access assignment ($GoneId) was removed from GDAP relationship $RelLabel since the last check. The security group it mapped no longer has its roles in that tenant." $Relationship $CustomerId $TenantName $false
            }
        }
    }

    # Relationships that were active last run and are not active now.
    if ($Previous -and $Previous.ActiveRelationshipIds) {
        $ActiveNow = @($Relationships | Where-Object { $_.status -eq 'active' } | ForEach-Object { [string]$_.id })
        foreach ($LostId in @($Previous.ActiveRelationshipIds | Where-Object { $_ -notin $ActiveNow })) {
            $Relationship = $Relationships | Where-Object { [string]$_.id -eq $LostId } | Select-Object -First 1
            if (-not $Relationship) { $Relationship = [pscustomobject]@{ id = $LostId; displayName = $LostId; status = 'missing'; customer = [pscustomobject]@{ tenantId = ''; displayName = '' } } }
            $CustomerId = [string]$Relationship.customer.tenantId
            $Managed = $ManagedTenants.ContainsKey($CustomerId)
            & $AddFinding "RelationshipLost|$LostId" 'RelationshipLost' ($Managed ? 'Error' : 'Warning') "GDAP relationship '$($Relationship.displayName)' for $($Relationship.customer.displayName) was active at the last check and is now $($Relationship.status)." $Relationship $CustomerId $Relationship.customer.displayName $false
        }
    }

    # Managed tenants with no active relationship at all.
    foreach ($CustomerId in @(if (-not $RelationshipsUnavailable) { $ManagedTenants.Keys })) {
        $Active = @($ByCustomer[$CustomerId] | Where-Object { $_.status -eq 'active' })
        if ($Active.Count -eq 0) {
            $Tenant = $ManagedTenants[$CustomerId]
            & $AddFinding "NoActiveRelationship|$CustomerId" 'NoActiveRelationship' 'Error' "$($Tenant.displayName) ($($Tenant.defaultDomainName)) is managed in CIPP but has no active GDAP relationship, so CIPP cannot reach it. Send a new GDAP invite, or remove the tenant from CIPP if the client has left." ([pscustomobject]@{ id = ''; displayName = '' }) $CustomerId $Tenant.displayName $true
        }
    }

    # Tenants whose Graph probe failed.
    foreach ($CustomerId in $TenantProbeErrors.Keys) {
        $Tenant = $ManagedTenants[[string]$CustomerId]
        $Name = if ($Tenant) { "$($Tenant.displayName) ($($Tenant.defaultDomainName))" } else { [string]$CustomerId }
        & $AddFinding "TenantAccessFailing|$CustomerId" 'TenantAccessFailing' 'Error' "CIPP could not call Graph in $($Name): $($TenantProbeErrors[$CustomerId])" ([pscustomobject]@{ id = ''; displayName = '' }) $CustomerId ($Tenant.displayName ?? $CustomerId) $true
    }

    # CIPP's own SAM app: the refresh token and the credential it signs in with.
    if ($SamStatus) {
        $Partner = [pscustomobject]@{ id = ''; displayName = 'CIPP-SAM' }
        if ($SamStatus.Ready -eq $false) {
            & $AddFinding 'SamAuthFailing' 'SamAuth' 'Error' "CIPP-SAM cannot get a token with its stored credentials and refresh token: $($SamStatus.Message). Every CIPP automation is affected. Re-run the SAM setup wizard or refresh the token under Settings > CIPP > Credentials." $Partner $PartnerTenantId 'Partner tenant' $true
        }
        $CredentialEnd = & $ToUtc $SamStatus.CredentialExpires
        if ($CredentialEnd) {
            $SamDays = [math]::Floor(($CredentialEnd - $Now).TotalDays)
            if ($SamDays -le $SamCredentialWarnDays) {
                & $AddFinding "SamCredentialExpiring|$($SamStatus.CredentialType)" 'SamCredential' 'Error' "The CIPP-SAM $($SamStatus.CredentialType.ToLower()) this instance signs in with expires on $($CredentialEnd.ToString('yyyy-MM-dd')) ($SamDays day(s)). The weekly token update normally renews it at 30 days, so that renewal is failing; check the 'Update Tokens' log entries." $Partner $PartnerTenantId 'Partner tenant' $true @{ DaysLeft = $SamDays }
            }
        }
    }

    $Order = @{ Error = 0; Warning = 1; Info = 2 }
    return @($Findings | Sort-Object -Property @{ Expression = { $Order[$_.Severity] } }, Tenant, Category)
}
