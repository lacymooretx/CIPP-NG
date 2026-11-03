function Get-CIPPAlertBreakGlassExclusionChange {
    <#
    .SYNOPSIS
        Alert from the Entra audit log when a break-glass Conditional Access exclusion is weakened
    .DESCRIPTION
        Raises High, naming the actor, when a Conditional Access policy update removes a registered account or a
        group holding one from its exclusions, or when something other than a registered account joins an
        exclusion group. Directory audit keeps only 30 days, which is how the cause of 3E's lost exclusion was
        lost, so this records it when it happens.

        Polls auditLogs/directoryAudits like Get-CIPPAlertBreakGlassActivity, because the Entra record holds the
        full before and after policy JSON. Each run scans the last LookbackHours (default 2);
        Write-AlertTrace -Append de-duplicates by event, so each event notifies once. A tenant with no registered
        account is skipped. Report only. Aspendora fork addition (Vikunja CIPP-56, CIPP-54).
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        [Parameter(Mandatory)]
        $TenantFilter
    )

    $Registered = @(Get-CIPPBreakGlassAccounts -TenantFilter $TenantFilter)
    if ($Registered.Count -eq 0) { return }

    $LookbackHours = if ($InputValue.BreakGlassLookbackHours) { [int]$InputValue.BreakGlassLookbackHours } else { 2 }
    $Cutoff = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $Graph = 'https://graph.microsoft.com/v1.0'
    $Warn = { param($What, $Err) Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Break-glass exclusion change: $($What): $((Get-CippException -Exception $Err).NormalizedError)" -sev Warning }

    $GroupNames = @{}
    $Accounts = foreach ($Row in $Registered) {
        $Id = [string]$Row.RowKey
        $GroupIds = @()
        try {
            $Groups = @(New-GraphGetRequest -uri "$Graph/users/$($Id)/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName" -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id })
            $GroupIds = @($Groups | ForEach-Object { [string]$_.id })
            foreach ($G in $Groups) { $GroupNames[[string]$G.id] = [string]$G.displayName }
        } catch { & $Warn "could not read groups of $Id, so a group removal may be missed" $_ }
        [pscustomobject]@{ Id = $Id; UserPrincipalName = $Row.UserPrincipalName; GroupIds = $GroupIds }
    }

    $ExclusionGroupIds = @()
    try {
        $Policies = @(New-GraphGetRequest -uri "$Graph/identity/conditionalAccess/policies" -tenantid $TenantFilter -ErrorAction Stop)
        $Excluded = @($Policies | ForEach-Object { $_.conditions.users.excludeGroups } | Where-Object { $_ })
        $ExclusionGroupIds = @($GroupNames.Keys | Where-Object { $_ -in $Excluded })
    } catch { & $Warn 'could not read policies, so additions to the exclusion group are not checked this run' $_ }

    $Events = [System.Collections.Generic.List[object]]::new()
    try {
        $Events.AddRange([object[]]@(New-GraphGetRequest -uri "$Graph/auditLogs/directoryAudits?`$filter=activityDisplayName eq 'Update conditional access policy' and activityDateTime ge $Cutoff&`$top=100" -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id }))
    } catch { & $Warn 'could not read policy updates' $_ }
    foreach ($GroupId in $ExclusionGroupIds) {
        try {
            $Events.AddRange([object[]]@(New-GraphGetRequest -uri "$Graph/auditLogs/directoryAudits?`$filter=activityDateTime ge $Cutoff and targetResources/any(t: t/id eq '$GroupId')&`$top=100" -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id }))
        } catch { & $Warn "could not read changes to group $GroupId" $_ }
    }

    $Rows = @(foreach ($AuditEvent in $Events) {
            try {
                Get-CIPPBreakGlassExclusionAuditFinding -AuditEvent $AuditEvent -Accounts @($Accounts) -GroupNames $GroupNames -ExclusionGroupIds $ExclusionGroupIds
            } catch { & $Warn "could not read audit event $($AuditEvent.id)" $_ }
        })
    if ($Rows.Count -eq 0) { return }
    @(Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows -Append | Where-Object { $_ })
}
