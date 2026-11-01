function Get-CIPPIntunePolicyAssignmentState {
    <#
    .SYNOPSIS
        Is an Intune policy assigned to anything, and to what (a short label)?
    .DESCRIPTION
        Pure. Input is the policy's assignments array (Graph shape: target.'@odata.type', target.groupId). Returns
        @{ Assigned; Label }. Assigned is true when at least one include target exists (All Devices, All Users, or a
        group). Exclusion-only and unassigned policies are not assigned: they apply to nothing.
        GroupNames (optional) maps group id -> display name for the label. Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [object[]]$Assignments = @(),
        [hashtable]$GroupNames = @{}
    )
    $Includes = [System.Collections.Generic.List[string]]::new()
    $Excludes = 0
    foreach ($A in @($Assignments)) {
        if ($null -eq $A) { continue }
        $T = $A.target ?? $A
        switch -Wildcard ([string]$T.'@odata.type') {
            # break: '*groupAssignmentTarget' below would also match an exclusion target.
            '*exclusionGroupAssignmentTarget' { $Excludes++; break }
            '*allDevicesAssignmentTarget' { $Includes.Add('All Devices') }
            '*allLicensedUsersAssignmentTarget' { $Includes.Add('All Users') }
            '*groupAssignmentTarget' {
                $Id = [string]$T.groupId
                $Includes.Add("Group '$($GroupNames[$Id] ?? $Id)'")
            }
        }
    }
    $Label = if ($Includes.Count -eq 0) { if ($Excludes -gt 0) { 'Exclusions only' } else { 'Not assigned' } } else { ($Includes -join ', ') + $(if ($Excludes -gt 0) { " (minus $Excludes exclusion group(s))" } else { '' }) }
    [pscustomobject]@{ Assigned = ($Includes.Count -gt 0); Label = $Label }
}
