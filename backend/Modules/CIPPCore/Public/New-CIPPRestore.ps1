function New-CIPPRestore {
    [CmdletBinding()]
    param (
        $TenantFilter,
        $Type = 'Scheduled',
        $RestoreValues,
        $APIName = 'CIPP Restore',
        $Headers
    )

    Write-Host "Scheduled Restore psproperties: $(([pscustomobject]$RestoreValues).psobject.Properties)"
    Write-LogMessage -headers $Headers -API $APINAME -message 'Restored backup' -Sev 'Debug'

    # Aspendora fork addition (Vikunja CIPP-23): opt-in safe restore-as-new. Only taken when the caller
    # sends safeRestore = true; without it the default restore below runs exactly as before.
    if (ConvertTo-CIPPBoolean -Value ([pscustomobject]$RestoreValues).safeRestore) {
        $SelectedTypes = ([pscustomobject]$RestoreValues).psobject.Properties | Where-Object { $_.Value -eq $true -and $_.Name -notin 'email', 'webhook', 'psa', 'backup', 'overwrite', 'safeRestore' } | Select-Object -ExpandProperty Name
        Write-Information "Safe restore-as-new of $($RestoreValues.backup) for tenant $TenantFilter"
        return New-CIPPSafeRestore -TenantFilter $TenantFilter -BackupName $RestoreValues.backup -Types $SelectedTypes -Headers $Headers -APIName $APIName
    }

    $RestoreData = foreach ($ScheduledBackup in ([pscustomobject]$RestoreValues).psobject.Properties | Where-Object { $_.Value -eq $true -and $_.Name -notin 'email', 'webhook', 'psa', 'backup', 'overwrite', 'safeRestore' } | Select-Object -ExpandProperty Name) {
        Write-Information "Restoring $ScheduledBackup for tenant $TenantFilter"
        New-CIPPRestoreTask -Task $ScheduledBackup -TenantFilter $TenantFilter -backup $RestoreValues.backup -overwrite $RestoreValues.overwrite -Headers $Headers -APIName $APIName
    }
    return $RestoreData
}
