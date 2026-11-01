function New-CIPPSafeRestore {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Safe restore-as-new: restores Intune and Conditional Access policies from a tenant backup as new, inert copies.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-23). Opt-in alternative to New-CIPPRestoreTask, reached
        from New-CIPPRestore when RestoreValues.safeRestore is true. It never modifies an existing object:

          - the backup is verified first; a Corrupt or Missing backup is not restored
          - the plan is Get-CIPPBackupRestorePlan -SafeMode against a fresh read of the tenant, so the
            restore does exactly what the Preview showed
          - every policy that is not identical to one already in the tenant is created under a new name,
            '<name> (restored yyyy-MM-dd)' (' #2', ' #3' when taken)
          - Conditional Access policies are created disabled, with conditions.users reduced to
            includeUsers ['None'] and no workload-identity targeting; Overwrite is $false and no groups
            are created, so New-CIPPCAPolicy refuses rather than updates if the name appeared meanwhile
          - Intune policies are created without assignments (no AssignTo, 'assignments' stripped)
          - other component types (users, groups, mail, CIPP settings) are reported as not restored
    .PARAMETER TenantFilter
        Tenant to restore into; must own the backup.
    .PARAMETER BackupName
        Scheduled backup name.
    .PARAMETER Types
        Component types selected for restore.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [Parameter(Mandatory = $true)][string]$BackupName,
        [string[]]$Types,
        $Headers,
        $APIName = 'CIPP Safe Restore'
    )

    $Results = [System.Collections.Generic.List[string]]::new()
    $SafeTypes = @('ca', 'intuneconfig', 'intunecompliance', 'intuneprotection')

    $Content = Get-CIPPBackupContent -Type 'Scheduled' -Name $BackupName -TenantFilter $TenantFilter
    if (-not $Content) {
        $Results.Add("Safe restore: backup $BackupName was not found.")
        return , $Results.ToArray()
    }
    $Integrity = Get-CIPPBackupIntegrityReport -Type 'Scheduled' -Content $Content
    if ($Integrity.Status -in @('Corrupt', 'Missing')) {
        $Message = "Safe restore aborted: backup $BackupName failed verification ($($Integrity.Status): $($Integrity.Detail))."
        Write-LogMessage -Headers $Headers -API $APIName -tenant $TenantFilter -message $Message -Sev 'Error'
        $Results.Add($Message)
        return , $Results.ToArray()
    }
    $Results.Add("Backup verification: $($Integrity.Status).")

    $Parsed = ConvertFrom-Json -InputObject $Content.Json.TrimStart([char]0xFEFF) -Depth 100 -NoEnumerate
    $Selected = @($Types | Where-Object { $_ })
    foreach ($Type in @($Selected | Where-Object { $_ -notin $SafeTypes })) {
        $Results.Add("Skipped $Type - safe restore-as-new covers Intune and Conditional Access policies only.")
    }
    $RestoreTypes = @($Selected | Where-Object { $_ -in $SafeTypes })
    if ($RestoreTypes.Count -eq 0) {
        $Results.Add('Safe restore: nothing to restore - select Conditional Access or Intune policies.')
        return , $Results.ToArray()
    }

    $BackupItems = Get-CIPPBackupItemList -Backup $Parsed -Types $RestoreTypes
    $Live = Get-CIPPBackupLiveSnapshot -TenantFilter $TenantFilter -Types $RestoreTypes
    foreach ($ReadError in $Live.Errors) { $Results.Add($ReadError) }
    $FailedReads = @($Live.FailedTypes)
    $LiveItems = Get-CIPPBackupItemList -Backup $Live.Backup -Types $RestoreTypes
    $Plan = Get-CIPPBackupRestorePlan -BackupItems $BackupItems -LiveItems $LiveItems -SafeMode $true -RestoreDate (Get-CIPPBackupRestoreDate)
    $ItemsByKey = @{}
    foreach ($Item in $BackupItems) { $ItemsByKey["$($Item.Type)`n$($Item.Key)"] = $Item }

    $Created = 0; $Skipped = 0; $Failed = 0
    foreach ($Entry in $Plan) {
        if ($Entry.Type -in $FailedReads) {
            # Without a current read we cannot prove the new name is free; do not guess.
            $Skipped++
            $Results.Add("Skipped $($Entry.Type) '$($Entry.Name)' - the tenant could not be read to check for name clashes.")
            continue
        }
        if (-not $Entry.NewName) {
            $Skipped++
            $Results.Add("$($Entry.Name): $($Entry.Action)")
            continue
        }
        $Item = $ItemsByKey["$($Entry.Type)`n$($Entry.Key)"]
        try {
            $Payload = ConvertTo-CIPPSafeRestorePayload -Item $Item -NewName $Entry.NewName
            if ($Entry.Type -eq 'ca') {
                $null = New-CIPPCAPolicy -RawJSON $Payload -TenantFilter $TenantFilter -State 'disabled' -Overwrite $false -ReplacePattern 'none' -CreateGroups $false -DisableSD $false -APIName $APIName -Headers $Headers
                $Results.Add("Created Conditional Access policy '$($Entry.NewName)' (disabled, no user/group targeting) from '$($Entry.Name)'.")
            } else {
                $null = Set-CIPPIntunePolicy -TemplateType $Payload.Type -TenantFilter $TenantFilter -DisplayName $Payload.DisplayName -Description $Payload.Description -RawJSON $Payload.TemplateJson -Headers $Headers -APIName $APIName
                $Results.Add("Created Intune policy '$($Entry.NewName)' (no assignments) from '$($Entry.Name)'.")
            }
            $Created++
            Write-LogMessage -Headers $Headers -API $APIName -tenant $TenantFilter -message "Safe restore created '$($Entry.NewName)' from backup $BackupName" -Sev 'Info'
        } catch {
            $Failed++
            $ErrorMessage = Get-CippException -Exception $_
            $Results.Add("Could not restore '$($Entry.Name)' as '$($Entry.NewName)': $($ErrorMessage.NormalizedError)")
            Write-LogMessage -Headers $Headers -API $APIName -tenant $TenantFilter -message "Safe restore could not create '$($Entry.NewName)': $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        }
    }
    $Results.Add("Safe restore finished: $Created created, $Skipped skipped, $Failed failed.")
    return , $Results.ToArray()
}
