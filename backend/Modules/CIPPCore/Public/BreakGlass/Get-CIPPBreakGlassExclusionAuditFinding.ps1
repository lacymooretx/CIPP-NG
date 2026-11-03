function Get-CIPPBreakGlassExclusionAuditFinding {
    <#
    .SYNOPSIS
        Decides whether one directory audit event weakened break-glass exclusions, and describes it.
    .DESCRIPTION
        Pure. Handles two events:

          Update conditional access policy - compares the before and after policy JSON in modifiedProperties and
          reports a registered account, or a group holding one, that left excludeUsers or excludeGroups. It says
          whether each affected account is still excluded another way, so a planned move from a user to a group
          reads differently from a real exposure.

          Add member to group - reports a member that is not a registered account joining an exclusion group.

        Failed operations changed nothing and are ignored. The row Id is the audit event id, so with
        Write-AlertTrace -Append each event notifies once however many runs see it. Rows carry no
        UserPrincipalName, because Get-AlertContentHash prefers it to Id and would merge separate events.
        Aspendora fork addition (Vikunja CIPP-56, CIPP-54).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$AuditEvent,
        # Registered accounts: @{ Id; UserPrincipalName; GroupIds }.
        [object[]]$Accounts = @(),
        # Group id -> display name, for groups holding a registered account.
        [hashtable]$GroupNames = @{},
        [string[]]$ExclusionGroupIds = @()
    )

    if ($AuditEvent.result -ne 'success') { return }

    $By = $AuditEvent.initiatedBy
    $Person = @($By.user.displayName, $By.user.userPrincipalName | Where-Object { $_ })
    $Actor = if ($Person.Count -eq 2) { "$($Person[0]) ($($Person[1]))" } elseif ($Person.Count -eq 1) { $Person[0] }
    if ($Actor -and $By.app.displayName) { $Actor = "$Actor via $($By.app.displayName)" }
    if (-not $Actor) { $Actor = @($By.app.displayName, 'unknown' | Where-Object { $_ })[0] }

    $Utc = ([datetimeoffset]$AuditEvent.activityDateTime).UtcDateTime
    $When = "$($Utc.ToString('yyyy-MM-dd HH:mm')) UTC"
    $Central = try { [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { $null }
    if ($Central) {
        $Local = [System.TimeZoneInfo]::ConvertTimeFromUtc($Utc, $Central)
        $When = "$($Local.ToString('yyyy-MM-dd HH:mm')) $(if ($Central.IsDaylightSavingTime($Local)) { 'CDT' } else { 'CST' }) ($($Utc.ToString('HH:mm')) UTC)"
    }

    $Label = { param($A) @($A.UserPrincipalName, $A.Id | Where-Object { $_ })[0] }

    if ($AuditEvent.activityDisplayName -eq 'Add member to group') {
        $Group = @($AuditEvent.targetResources | Where-Object { $_.type -eq 'Group' -and $_.id -in $ExclusionGroupIds })[0]
        if (-not $Group) { return }
        $RegisteredIds = @($Accounts | ForEach-Object { [string]$_.Id })
        $Member = @($AuditEvent.targetResources | Where-Object { $_.id -ne $Group.id })[0]
        if (-not $Member -or [string]$Member.id -in $RegisteredIds) { return }
        $MemberName = @($Member.userPrincipalName, $Member.displayName, $Member.id | Where-Object { $_ })[0]
        $GroupName = $GroupNames[[string]$Group.id] ?? $Group.id
        return [pscustomobject]@{
            Id       = "Audit|$($AuditEvent.id)"
            Severity = 'High'
            Type     = 'ExclusionGroupMemberAdded'
            Group    = $GroupName
            Member   = $MemberName
            Actor    = $Actor
            When     = $When
            Message  = "$Actor added $MemberName to break-glass exclusion group '$GroupName' at $When. It is not a registered break-glass account, and it now skips every Conditional Access policy that excludes the group. If this was not planned, remove it and treat the change as a possible attack."
        }
    }

    if ($AuditEvent.activityDisplayName -ne 'Update conditional access policy') { return }
    $Target = @($AuditEvent.targetResources | Where-Object { $_.type -eq 'Policy' })[0]
    $Property = @($Target.modifiedProperties | Where-Object { $_.displayName -eq 'ConditionalAccessPolicy' })[0]
    if (-not $Property.oldValue -or -not $Property.newValue) { return }
    $Old = ($Property.oldValue | ConvertFrom-Json -ErrorAction Stop).conditions.users
    $New = ($Property.newValue | ConvertFrom-Json -ErrorAction Stop).conditions.users

    $RemovedUsers = @($Old.excludeUsers | Where-Object { $_ -and $_ -notin @($New.excludeUsers) })
    $RemovedGroups = @($Old.excludeGroups | Where-Object { $_ -and $_ -notin @($New.excludeGroups) })

    $RemovedNames = [System.Collections.Generic.List[string]]::new()
    $Affected = [System.Collections.Generic.List[object]]::new()
    foreach ($A in $Accounts) {
        if ([string]$A.Id -in $RemovedUsers) {
            $RemovedNames.Add("account $(& $Label $A)")
            $Affected.Add($A)
        } elseif (@($A.GroupIds | Where-Object { $_ -in $RemovedGroups }).Count -gt 0) {
            $Affected.Add($A)
        }
    }
    foreach ($GroupId in $RemovedGroups) {
        if ($GroupNames.ContainsKey([string]$GroupId)) { $RemovedNames.Add("group '$($GroupNames[[string]$GroupId])'") }
    }
    if ($RemovedNames.Count -eq 0) { return }

    $Exposed = @($Affected | Where-Object {
            $Account = $_
            [string]$Account.Id -notin @($New.excludeUsers) -and @($Account.GroupIds | Where-Object { $_ -in @($New.excludeGroups) }).Count -eq 0
        } | ForEach-Object { & $Label $_ })
    $Outcome = if ($Exposed.Count -gt 0) {
        "$($Exposed -join ', ') NOT excluded from this policy any more, so a mistake in it can lock out the emergency account."
    } else {
        'The accounts are still excluded another way, so check this was a planned move.'
    }
    $PolicyName = @($Target.displayName, $Target.id | Where-Object { $_ })[0]
    [pscustomobject]@{
        Id       = "Audit|$($AuditEvent.id)"
        Severity = 'High'
        Type     = 'ExclusionRemoved'
        Policy   = $PolicyName
        PolicyId = $Target.id
        Removed  = $RemovedNames -join ', '
        Exposed  = $Exposed -join ', '
        Actor    = $Actor
        When     = $When
        Message  = "$Actor removed the break-glass exclusion ($($RemovedNames -join ', ')) from Conditional Access policy '$PolicyName' at $When. $Outcome"
    }
}
