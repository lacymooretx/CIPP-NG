function Invoke-ExecBackupRestorePreview {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        CIPP.Backup.Read
    .SYNOPSIS
        Preview what restoring a tenant backup would do, per object, without writing anything
    .DESCRIPTION
        Reads the tenant's current state with the same capture the backup uses (GET requests only)
        and compares each backed-up object with it. Classification: Create (nothing with that
        name/identity exists), Identical (exists and matches, volatile fields and assignments
        ignored), Conflict (exists with the same name but different content - Changes shows tenant
        value as Before and backup value as After) or Unparsed (the backup holds an error string).
        Action describes what the selected mode would do: the default restore (honouring Overwrite,
        and showing that Intune restores overwrite same-name policies) or, with SafeMode=true, the
        safe restore-as-new ('<name> (restored yyyy-MM-dd)', CA disabled, no assignments).
        Parameters: BackupName, tenantFilter (required; must own the backup), Types (component
        filter, array or comma-separated; default all components in the backup), SafeMode, Overwrite.
        Aspendora fork addition (Vikunja CIPP-23).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $BackupName = [string]($Request.Body.BackupName ?? $Request.Query.BackupName)
    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $SafeMode = ConvertTo-CIPPBoolean -Value ($Request.Body.SafeMode ?? $Request.Query.SafeMode)
    $Overwrite = ConvertTo-CIPPBoolean -Value ($Request.Body.Overwrite ?? $Request.Query.Overwrite)
    $RawTypes = $Request.Body.Types ?? $Request.Query.Types
    $RequestedTypes = @(foreach ($T in @($RawTypes)) {
            if ($null -eq $T) { continue }
            $V = if ($T -is [string]) { $T } else { [string]($T.value ?? $T) }
            foreach ($Part in ($V -split ',')) { if ($Part.Trim()) { $Part.Trim() } }
        })
    $Respond = { param($Code, $Body) [HttpResponseContext]@{ StatusCode = $Code; Body = $Body } }

    # Components New-CIPPBackupTask can re-read from the tenant.
    $Capturable = @('users', 'groups', 'ca', 'intuneconfig', 'intunecompliance', 'intuneprotection', 'antispam', 'antiphishing', 'teamsvoice', 'CippWebhookAlerts', 'CippScriptedAlerts', 'CippCustomVariables')

    if (-not $BackupName) { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'BackupName is required.' }) }
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'tenantFilter must name the tenant the backup belongs to.' }) }

    try {
        $Content = Get-CIPPBackupContent -Type 'Scheduled' -Name $BackupName -TenantFilter $TenantFilter
    } catch {
        if ($_.Exception.Message -like '*does not belong to tenant*') {
            return (& $Respond ([HttpStatusCode]::Forbidden) @{ Results = $_.Exception.Message })
        }
        $ErrorMessage = Get-CippException -Exception $_
        return (& $Respond ([HttpStatusCode]::InternalServerError) @{ Results = "Could not load backup: $($ErrorMessage.NormalizedError)" })
    }
    if (-not $Content) { return (& $Respond ([HttpStatusCode]::NotFound) @{ Results = "Backup $BackupName not found." }) }
    if (-not $Content.Readable) { return (& $Respond ([HttpStatusCode]::UnprocessableEntity) @{ Results = "Backup $BackupName could not be read from storage." }) }

    try {
        $Integrity = Get-CIPPBackupIntegrityReport -Type 'Scheduled' -Content $Content
        $Parsed = ConvertFrom-Json -InputObject $Content.Json.TrimStart([char]0xFEFF) -Depth 100 -NoEnumerate -ErrorAction Stop
        $AllItems = Get-CIPPBackupItemList -Backup $Parsed
        $Present = @($AllItems | ForEach-Object { $_.Type } | Sort-Object -Unique)
        $Types = if ($RequestedTypes.Count -gt 0) { @($RequestedTypes | Where-Object { $_ -in $Present }) } else { $Present }
        $NotCapturable = @($Types | Where-Object { $_ -notin $Capturable })
        $Types = @($Types | Where-Object { $_ -in $Capturable })

        $BackupItems = @($AllItems | Where-Object { $_.Type -in $Types })
        $ReadErrors = @()
        $LiveItems = @()
        if ($Types.Count -gt 0) {
            $Live = Get-CIPPBackupLiveSnapshot -TenantFilter $TenantFilter -Types $Types
            $ReadErrors = @($Live.Errors)
            $LiveItems = Get-CIPPBackupItemList -Backup $Live.Backup -Types $Types
            # A component the tenant could not be read for would otherwise show every object as Create.
            $BackupItems = @($BackupItems | Where-Object { $_.Type -notin @($Live.FailedTypes) })
        }
        $Plan = Get-CIPPBackupRestorePlan -BackupItems $BackupItems -LiveItems $LiveItems -SafeMode $SafeMode -Overwrite $Overwrite -RestoreDate (Get-CIPPBackupRestoreDate)
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'ExecBackupRestorePreview' -tenant $TenantFilter -message "Could not preview restore of $($BackupName): $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return (& $Respond ([HttpStatusCode]::InternalServerError) @{ Results = "Could not preview the restore: $($ErrorMessage.NormalizedError)" })
    }

    $Count = { param($Classification) @($Plan | Where-Object { $_.Classification -eq $Classification }).Count }
    return (& $Respond ([HttpStatusCode]::OK) @{
            Results = [pscustomobject][ordered]@{
                BackupName    = $BackupName
                TenantFilter  = $TenantFilter
                SafeMode      = $SafeMode
                Overwrite     = $Overwrite
                Integrity     = [pscustomobject]@{ Status = $Integrity.Status; Detail = $Integrity.Detail }
                Types         = @($Types)
                NotPreviewed  = @($NotCapturable)
                ReadErrors    = @($ReadErrors)
                Summary       = [pscustomobject][ordered]@{
                    Create    = & $Count 'Create'
                    Identical = & $Count 'Identical'
                    Conflict  = & $Count 'Conflict'
                    Unparsed  = & $Count 'Unparsed'
                    NewCopies = @($Plan | Where-Object { $_.NewName }).Count
                }
                Objects       = @($Plan)
            }
        })
}
