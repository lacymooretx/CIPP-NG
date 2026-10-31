function Test-CIPPIntunePolicyHygiene {
    <#
    .SYNOPSIS
        Intune assignment hygiene rules, from already-collected policies and group facts.
    .DESCRIPTION
        Pure rules, no Graph calls; Get-CIPPIntunePolicyHygiene collects the inputs. Findings:
          Unassigned     - the policy has no assignments at all (apps are not checked: only assigned apps are read)
          ExclusionOnly  - every assignment is an exclusion, so the policy lands nowhere
          MissingGroup   - an assignment points at a group that no longer exists
          EmptyGroup     - an assignment points at a group with no members (Warning for an include, Info for an
                           exclusion, which cancels nothing)
        A group whose existence or membership could not be read is never reported as missing or empty.
        Each finding has a stable Key. Returns @{ Findings; Summary }.
        Aspendora fork addition (Vikunja CIPP-19).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # @{ Id; Name; Type; Family; Assignments }
        [object[]]$Policies = @(),
        # groupId -> @{ Exists = $true|$false|$null; DisplayName; MemberCount = int or $null; Dynamic = bool }
        [hashtable]$Groups = @{}
    )

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Add = {
        param($Category, $Severity, $Policy, $Group, $Message)
        $Findings.Add([pscustomobject]@{
                Key        = "$Category|$($Policy.Id)$(if ($Group) { "|$Group" })"
                Severity   = $Severity
                Category   = $Category
                PolicyType = [string]$Policy.Type
                PolicyName = [string]$Policy.Name
                PolicyId   = [string]$Policy.Id
                Family     = [string]$Policy.Family
                Group      = [string]$Group
                Message    = $Message
            })
    }

    $Total = 0
    foreach ($Policy in @($Policies)) {
        if ($null -eq $Policy) { continue }
        $Total++
        if ($Policy.AssignmentsUnknown) { continue }
        $Assignments = @($Policy.Assignments | Where-Object { $_.target })
        if ($Assignments.Count -eq 0) {
            if ($Policy.Family -ne 'MobileApps') {
                & $Add 'Unassigned' 'Info' $Policy '' "$($Policy.Type) '$($Policy.Name)' has no assignments, so it does nothing. Assign it or delete it."
            }
            continue
        }

        $Types = @($Assignments | ForEach-Object { ([string]$_.target.'@odata.type') -replace '^#?microsoft\.graph\.', '' })
        if (@($Types | Where-Object { $_ -notmatch '^exclusion' }).Count -eq 0) {
            & $Add 'ExclusionOnly' 'Warning' $Policy '' "$($Policy.Type) '$($Policy.Name)' is assigned only through exclusions, so it lands on no device or user. It probably lost its include assignment."
        }

        $Seen = @{}
        foreach ($A in $Assignments) {
            $GroupId = [string]$A.target.groupId
            if (-not $GroupId) { continue }
            $IsExclusion = ([string]$A.target.'@odata.type') -match 'exclusion'
            $SeenKey = "$GroupId|$IsExclusion"
            if ($Seen.ContainsKey($SeenKey)) { continue }
            $Seen[$SeenKey] = $true
            $G = $Groups[$GroupId]
            if ($null -eq $G) { continue }
            $Label = if ($G.DisplayName) { "'$($G.DisplayName)'" } else { $GroupId }
            $Role = if ($IsExclusion) { 'exclusion' } else { 'assignment' }
            if ($G.Exists -eq $false) {
                & $Add 'MissingGroup' ($IsExclusion ? 'Warning' : 'Error') $Policy $GroupId "$($Policy.Type) '$($Policy.Name)' has an $Role to group $GroupId, which no longer exists. $(if ($IsExclusion) { 'Whatever that exclusion protected is now included.' } else { 'That assignment targets nobody.' })"
                continue
            }
            if ($G.Exists -eq $true -and $G.MemberCount -eq 0 -and $null -ne $G.MemberCount) {
                $Dyn = if ($G.Dynamic) { ' It is a dynamic group: check its membership rule.' } else { '' }
                & $Add 'EmptyGroup' ($IsExclusion ? 'Info' : 'Warning') $Policy $GroupId "$($Policy.Type) '$($Policy.Name)' has an $Role to group $Label, which has no members.$Dyn"
            }
        }
    }

    $ByCategory = [ordered]@{}
    foreach ($C in @('Unassigned', 'ExclusionOnly', 'MissingGroup', 'EmptyGroup')) { $ByCategory[$C] = @($Findings | Where-Object Category -EQ $C).Count }
    $ByType = [ordered]@{}
    foreach ($F in @($Findings | Group-Object PolicyType | Sort-Object Name)) { $ByType[$F.Name] = $F.Count }

    [pscustomobject]@{
        Findings = @($Findings | Sort-Object @{ Expression = { @{ Error = 0; Warning = 1; Info = 2 }[$_.Severity] } }, Category, PolicyType, PolicyName)
        Summary  = [pscustomobject]@{
            PoliciesChecked = $Total
            Findings        = $Findings.Count
            Errors          = @($Findings | Where-Object Severity -EQ 'Error').Count
            Warnings        = @($Findings | Where-Object Severity -EQ 'Warning').Count
            Info            = @($Findings | Where-Object Severity -EQ 'Info').Count
            ByCategory      = [pscustomobject]$ByCategory
            ByPolicyType    = [pscustomobject]$ByType
        }
    }
}
