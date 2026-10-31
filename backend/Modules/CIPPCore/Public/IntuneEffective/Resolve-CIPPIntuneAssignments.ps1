function Resolve-CIPPIntuneAssignments {
    <#
    .SYNOPSIS
        Works out which Intune policies land on one device, and why, from already-collected data.
    .DESCRIPTION
        Pure rules, no Graph calls; Get-CIPPIntuneEffectivePolicy collects the inputs.

        Targets understood: groupAssignmentTarget and exclusionGroupAssignmentTarget (matched on the device's and
        the primary user's TRANSITIVE group membership), allDevicesAssignmentTarget, allLicensedUsersAssignmentTarget
        / allUsersAssignmentTarget (only when the device has a primary user), and their exclusion forms.
        EXCLUSIONS WIN, as they do in Intune: a matched exclusion cancels the include. For apps an exclusion only
        cancels includes with the same intent (required / available / uninstall), because that is how app
        exclusions are stored.

        Assignment filters: evaluated with Test-CIPPIntuneAssignmentFilterRule. When the rule cannot be evaluated
        reliably the row says "Applies unless filter excludes (not evaluated)"; a filter result is never claimed
        that was not computed.

        Platform: a policy whose platform is known and differs from the device's is skipped (counted in
        PlatformSkipped). Unknown platform is never grounds to skip.

        Returns @{ Rows; PlatformSkipped }. Each row: PolicyId, PolicyName, PolicyType, Family, Platform, Intent,
        Status, Applies, TargetedVia, Filter, FilterRule, FilterMode, FilterResult, ExcludedBy, Notes.
        Status is one of: Applies, Applies unless filter excludes (not evaluated), Excluded, Filtered out.
        Aspendora fork addition (Vikunja CIPP-19).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # @{ Id; Name; Type; Family; Platforms (string[] from Get-CIPPIntunePolicyPlatform); Assignments (Graph objects) }
        [object[]]$Policies = @(),
        # windows / macOS / iOS / android / linux, or $null when unknown.
        [string]$DevicePlatform,
        # Filter-rule properties: deviceName, manufacturer, model, osVersion, enrollmentProfileName, deviceOwnership ...
        [hashtable]$DeviceProperties = @{},
        [string[]]$DeviceGroupIds = @(),
        [string[]]$UserGroupIds = @(),
        [bool]$HasUser = $false,
        [string]$UserName,
        # groupId -> display name
        [hashtable]$GroupNames = @{},
        # filterId -> @{ displayName; rule }
        [hashtable]$Filters = @{}
    )

    $DeviceGroups = [System.Collections.Generic.HashSet[string]]::new([string[]]@($DeviceGroupIds | Where-Object { $_ }), [System.StringComparer]::OrdinalIgnoreCase)
    $UserGroups = [System.Collections.Generic.HashSet[string]]::new([string[]]@($UserGroupIds | Where-Object { $_ }), [System.StringComparer]::OrdinalIgnoreCase)
    $UserLabel = if ($UserName) { "user $UserName" } else { 'primary user' }
    $GroupLabel = { param($Id) if ($GroupNames.ContainsKey([string]$Id) -and $GroupNames[[string]$Id]) { "'$($GroupNames[[string]$Id])'" } else { "'$Id'" } }

    $Rows = [System.Collections.Generic.List[object]]::new()
    $PlatformSkipped = 0

    foreach ($Policy in @($Policies)) {
        if ($null -eq $Policy) { continue }
        $Platforms = @($Policy.Platforms | Where-Object { $_ })
        if ($DevicePlatform -and $Platforms.Count -gt 0 -and $DevicePlatform -notin $Platforms) { $PlatformSkipped++; continue }

        # intent -> lists of matched includes / exclusions
        $ByIntent = [ordered]@{}
        foreach ($Assignment in @($Policy.Assignments)) {
            $Target = $Assignment.target
            if (-not $Target) { continue }
            $Intent = if ($Assignment.intent -and $Assignment.intent -ne 'apply') { [string]$Assignment.intent } else { '' }
            $GroupId = [string]$Target.groupId
            $Type = ([string]$Target.'@odata.type') -replace '^#?microsoft\.graph\.', ''

            $Match = $null # @{ Kind = 'Include'|'Exclude'; Via; Principal = 'device'|'user' }
            switch ($Type) {
                'groupAssignmentTarget' {
                    if ($GroupId -and $DeviceGroups.Contains($GroupId)) { $Match = @{ Kind = 'Include'; Via = "Group $(& $GroupLabel $GroupId) (device member)"; Principal = 'device' } }
                    elseif ($GroupId -and $HasUser -and $UserGroups.Contains($GroupId)) { $Match = @{ Kind = 'Include'; Via = "Group $(& $GroupLabel $GroupId) ($UserLabel member)"; Principal = 'user' } }
                }
                'exclusionGroupAssignmentTarget' {
                    if ($GroupId -and $DeviceGroups.Contains($GroupId)) { $Match = @{ Kind = 'Exclude'; Via = "Group $(& $GroupLabel $GroupId) (device member)"; Principal = 'device' } }
                    elseif ($GroupId -and $HasUser -and $UserGroups.Contains($GroupId)) { $Match = @{ Kind = 'Exclude'; Via = "Group $(& $GroupLabel $GroupId) ($UserLabel member)"; Principal = 'user' } }
                }
                'allDevicesAssignmentTarget' { $Match = @{ Kind = 'Include'; Via = 'All Devices'; Principal = 'device' } }
                'exclusionAllDevicesAssignmentTarget' { $Match = @{ Kind = 'Exclude'; Via = 'All Devices'; Principal = 'device' } }
                'allLicensedUsersAssignmentTarget' { if ($HasUser) { $Match = @{ Kind = 'Include'; Via = "All Users (via $UserLabel)"; Principal = 'user' } } }
                'allUsersAssignmentTarget' { if ($HasUser) { $Match = @{ Kind = 'Include'; Via = "All Users (via $UserLabel)"; Principal = 'user' } } }
                'exclusionAllUsersAssignmentTarget' { if ($HasUser) { $Match = @{ Kind = 'Exclude'; Via = "All Users (via $UserLabel)"; Principal = 'user' } } }
            }
            if (-not $Match) { continue }

            if (-not $ByIntent.Contains($Intent)) { $ByIntent[$Intent] = @{ Includes = [System.Collections.Generic.List[object]]::new(); Excludes = [System.Collections.Generic.List[object]]::new() } }
            if ($Match.Kind -eq 'Exclude') { $ByIntent[$Intent].Excludes.Add($Match); continue }

            # Filter on the include.
            $FilterId = [string]$Target.deviceAndAppManagementAssignmentFilterId
            $FilterMode = [string]$Target.deviceAndAppManagementAssignmentFilterType
            $Match.FilterMode = ''; $Match.Filter = ''; $Match.FilterRule = ''; $Match.FilterResult = ''; $Match.Outcome = 'Applies'
            if ($FilterId -and $FilterMode -in @('include', 'exclude')) {
                $Match.FilterMode = $FilterMode
                $Def = $Filters[$FilterId]
                $Match.Filter = if ($Def.displayName) { [string]$Def.displayName } else { $FilterId }
                $Match.FilterRule = [string]$Def.rule
                $Eval = if ($Def) { Test-CIPPIntuneAssignmentFilterRule -Rule ([string]$Def.rule) -Device $DeviceProperties } else { $null }
                if ($null -eq $Eval) {
                    $Match.FilterResult = if ($Def) { 'Not evaluated' } else { 'Not evaluated (filter not found)' }
                    $Match.Outcome = 'Unknown'
                } else {
                    $Match.FilterResult = if ($Eval) { 'Device matches rule' } else { 'Device does not match rule' }
                    $Applies = if ($FilterMode -eq 'include') { $Eval } else { -not $Eval }
                    $Match.Outcome = if ($Applies) { 'Applies' } else { 'FilteredOut' }
                }
            }
            $ByIntent[$Intent].Includes.Add($Match)
        }

        foreach ($Intent in $ByIntent.Keys) {
            $Includes = @($ByIntent[$Intent].Includes)
            $Excludes = @($ByIntent[$Intent].Excludes)
            if ($Includes.Count -eq 0 -and $Excludes.Count -eq 0) { continue }
            # An exclusion with nothing to cancel is not something landing on the device; skip it.
            if ($Includes.Count -eq 0) { continue }

            $Definite = @($Includes | Where-Object { $_.Outcome -eq 'Applies' })
            $Unknown = @($Includes | Where-Object { $_.Outcome -eq 'Unknown' })
            $Notes = [System.Collections.Generic.List[string]]::new()

            if ($Excludes.Count -gt 0) {
                $Status = 'Excluded'
                $Principals = @($Includes.Principal | Sort-Object -Unique)
                $ExPrincipals = @($Excludes.Principal | Sort-Object -Unique)
                if (@($ExPrincipals | Where-Object { $_ -notin $Principals }).Count -gt 0) {
                    $Notes.Add('Included via a ' + ($Principals -join '/') + ' target but excluded via a ' + ($ExPrincipals -join '/') + ' group. Microsoft does not support mixing user and device groups across include and exclude; verify on the device that the exclusion is honoured.')
                }
            } elseif ($Definite.Count -gt 0) {
                $Status = 'Applies'
            } elseif ($Unknown.Count -gt 0) {
                $Status = 'Applies unless filter excludes (not evaluated)'
            } else {
                $Status = 'Filtered out'
            }

            $Shown = if ($Definite.Count -gt 0) { $Definite } elseif ($Unknown.Count -gt 0) { $Unknown } else { $Includes }
            $Rows.Add([pscustomobject]@{
                    PolicyId     = [string]$Policy.Id
                    PolicyName   = [string]$Policy.Name
                    PolicyType   = [string]$Policy.Type
                    Family       = [string]$Policy.Family
                    Platform     = ($Platforms -join ', ')
                    Intent       = $Intent
                    Status       = $Status
                    Applies      = ($Status -eq 'Applies')
                    TargetedVia  = (@($Includes.Via | Sort-Object -Unique) -join '; ')
                    Filter       = (@($Shown.Filter | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
                    FilterRule   = (@($Shown.FilterRule | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
                    FilterMode   = (@($Shown.FilterMode | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
                    FilterResult = (@($Shown.FilterResult | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
                    ExcludedBy   = (@($Excludes.Via | Sort-Object -Unique) -join '; ')
                    Notes        = ($Notes -join ' ')
                })
        }
    }

    $Order = @{ 'Applies' = 0; 'Applies unless filter excludes (not evaluated)' = 1; 'Excluded' = 2; 'Filtered out' = 3 }
    [pscustomobject]@{
        Rows            = @($Rows | Sort-Object @{ Expression = { $Order[$_.Status] } }, PolicyType, PolicyName)
        PlatformSkipped = $PlatformSkipped
    }
}
