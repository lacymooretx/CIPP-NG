function Get-CIPPBackupRestorePlan {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Works out, per backed-up object, what a restore would do against the tenant as it is now. Writes nothing.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23). Pure: compares two item lists (backup vs. a live
        snapshot taken with Get-CIPPBackupLiveSnapshot) and returns one plan entry per backup object:

          Classification  Create     nothing with this name/identity exists in the tenant
                          Identical  it exists and matches the backup (volatile fields and assignments ignored)
                          Conflict   it exists with the same name/identity but different content (Changes:
                                     Before = tenant, After = backup)
                          Unparsed   the backup holds an error string for this entry, not an object
          Action          what the selected restore mode will do with it
          NewName         safe mode only: the name the restored copy gets

        Default mode describes what New-CIPPRestoreTask does today (including that Intune restores
        overwrite a same-name policy whatever the overwrite setting). Safe mode (restore-as-new) never
        touches an existing object: Intune and Conditional Access policies that are not identical are
        created as new policies named '<name> (restored yyyy-MM-dd)' (with ' #2'... when that name is
        taken), CA policies disabled and without user/group targeting, Intune policies without
        assignments. Other component types are not restored in safe mode.
    .PARAMETER BackupItems
        Get-CIPPBackupItemList output for the backup.
    .PARAMETER LiveItems
        Get-CIPPBackupItemList output for the live snapshot.
    .PARAMETER SafeMode
        Plan a safe restore-as-new instead of the default restore.
    .PARAMETER Overwrite
        The default restore's overwrite setting (ignored in safe mode).
    .PARAMETER RestoreDate
        Date used in the restored-name suffix, yyyy-MM-dd.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][object[]]$BackupItems = @(),
        [AllowNull()][object[]]$LiveItems = @(),
        [bool]$SafeMode = $false,
        [bool]$Overwrite = $false,
        [string]$RestoreDate = (Get-Date).ToString('yyyy-MM-dd')
    )

    $SafeTypes = @('ca', 'intuneconfig', 'intunecompliance', 'intuneprotection')
    $BackupTypes = @($BackupItems | Where-Object { $null -ne $_ } | ForEach-Object { $_.Type } | Sort-Object -Unique)
    $Live = @($LiveItems | Where-Object { $null -ne $_ -and $_.Type -in $BackupTypes -and -not $_.Unparsed })
    $Parsed = @($BackupItems | Where-Object { $null -ne $_ -and -not $_.Unparsed })

    $Diff = Compare-CIPPBackupItemSet -BaseItems $Live -CompareItems $Parsed -UseAltKey

    # Names already taken in the tenant, per component type, for the restored-name suffix.
    $TakenNames = @{}
    foreach ($Item in $Live) {
        if (-not $TakenNames.ContainsKey($Item.Type)) { $TakenNames[$Item.Type] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
        $null = $TakenNames[$Item.Type].Add([string]$Item.Name)
    }
    $NewNameFor = {
        param([string]$Type, [string]$Name)
        if (-not $TakenNames.ContainsKey($Type)) { $TakenNames[$Type] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
        $Candidate = "$Name (restored $RestoreDate)"
        $n = 1
        while ($TakenNames[$Type].Contains($Candidate)) {
            $n++
            $Candidate = "$Name (restored $RestoreDate #$n)"
        }
        $null = $TakenNames[$Type].Add($Candidate)
        return $Candidate
    }

    $DefaultAction = {
        param([string]$Type, [string]$Classification)
        $Exists = $Classification -ne 'Create'
        switch -Regex ($Type) {
            '^users$' { if (-not $Exists) { 'Create user with a temporary password' } elseif ($Overwrite) { 'Overwrite the existing user (PATCH)' } else { 'Skip - user exists and overwrite is off' }; break }
            '^groups$' { if (-not $Exists) { 'Create group' } elseif ($Overwrite) { 'Overwrite the existing group (PATCH)' } else { 'Skip - group exists and overwrite is off' }; break }
            '^ca$' { if (-not $Exists) { 'Create policy with the state stored in the backup' } elseif ($Overwrite) { 'Overwrite the existing policy (its current state is kept)' } else { 'Fail - a policy with this name exists and overwrite is off' }; break }
            '^intune' { if (-not $Exists) { 'Create policy' } else { 'Overwrite the existing policy with the same name (Intune restore ignores the overwrite setting)' }; break }
            '^(antispam|antiphishing)$' { if (-not $Exists) { 'Create' } elseif ($Overwrite) { 'Overwrite the existing policy/rule' } else { 'Skip - exists and overwrite is off' }; break }
            '^CippCustomVariables$' { if (-not $Exists) { 'Create variable' } elseif ($Overwrite) { 'Overwrite the existing variable' } else { 'Skip - variable exists and overwrite is off' }; break }
            '^(CippWebhookAlerts|CippScriptedAlerts)$' { 'Write the row, replacing any row with the same key'; break }
            '^teamsvoice$' { if (-not $Exists) { 'Assign the number' } elseif ($Classification -eq 'Identical') { 'No change - already assigned to the same holder' } elseif ($Overwrite) { 'Reassign the number' } else { 'Skip - number is held differently and overwrite is off' }; break }
            default { if (-not $Exists) { 'Create' } else { 'Restore over the existing object' } }
        }
    }

    $Plan = [System.Collections.Generic.List[object]]::new()
    foreach ($Entry in @($Diff)) {
        if ($Entry.Status -eq 'Removed') { continue } # in the tenant but not in the backup: a restore does not touch it
        $Backup = $Entry.Compare
        $Existing = $Entry.Base
        $Classification = switch ($Entry.Status) { 'Added' { 'Create' } 'Unchanged' { 'Identical' } default { 'Conflict' } }
        $NewName = $null
        if ($SafeMode) {
            if ($Backup.Type -notin $SafeTypes) {
                $Action = 'Not restored - safe restore-as-new covers Intune and Conditional Access policies only'
            } elseif ($Classification -eq 'Identical') {
                $Action = 'Skip - an identical policy already exists'
            } else {
                $NewName = & $NewNameFor $Backup.Type $Backup.Name
                $Action = if ($Backup.Type -eq 'ca') { "Create new policy '$NewName', disabled, with user/group targeting removed" } else { "Create new policy '$NewName' without assignments" }
            }
        } else {
            $Action = & $DefaultAction $Backup.Type $Classification
            if ($Classification -eq 'Identical' -and $Backup.Type -notmatch '^(ca|teamsvoice)$') { $Action = "$Action (content is identical, no effective change)" }
        }
        $Plan.Add([pscustomobject][ordered]@{
                Type           = $Backup.Type
                Key            = $Backup.Key
                Name           = $Backup.Name
                Classification = $Classification
                Action         = $Action
                NewName        = $NewName
                ExistingName   = if ($Existing) { $Existing.Name } else { $null }
                Changes        = @($Entry.Changes)
            })
    }

    foreach ($Item in @($BackupItems | Where-Object { $null -ne $_ -and $_.Unparsed })) {
        $Plan.Add([pscustomobject][ordered]@{
                Type           = $Item.Type
                Key            = $Item.Key
                Name           = $Item.Name
                Classification = 'Unparsed'
                Action         = 'Skip - the backup holds an error message for this entry, not an object'
                NewName        = $null
                ExistingName   = $null
                Changes        = @()
            })
    }
    return , $Plan.ToArray()
}
