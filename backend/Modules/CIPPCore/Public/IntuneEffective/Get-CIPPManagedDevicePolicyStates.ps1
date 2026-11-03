function Get-CIPPManagedDevicePolicyStates {
    <#
    .SYNOPSIS
        One managed device's configuration profile or compliance policy states, one row per policy, with error detail.
    .DESCRIPTION
        Read-only. Reads managedDevices/{id}/{Collection}, which returns one row per policy PER CONTEXT (each signed-in
        user plus "System account"), and collapses them to one row per policy with the worst state, keeping the contexts.

        The states collection returns settingStates as an empty array; $expand=settingStates and
        {Collection}/{policyId} are refused, and $filter on settingStates errors. The only working route is
        {Collection}/{policyId}/settingStates, so it is read per policy (verified on aspendora.com, 2026-11-03):
          default             only policies in a failing state, returning only their failing settings
          -IncludeAllSettings every policy, every setting (one paged read per policy)

        A failed collection read throws, so a caller can never report it as "no policies". A failed settingStates read
        is recorded on the row (SettingsError) and in Errors; it does not discard the other policies.
        Returns @{ Results; Errors }. Aspendora fork addition (CIPP and ControlR integration).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [Parameter(Mandatory)][string]$ManagedDeviceId,
        [Parameter(Mandatory)][ValidateSet('deviceConfigurationStates', 'deviceCompliancePolicyStates')][string]$Collection,
        [switch]$IncludeAllSettings
    )

    $Base = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$ManagedDeviceId/$Collection"
    $Failing = @('error', 'conflict', 'nonCompliant')
    $Rank = @{ error = 0; conflict = 1; nonCompliant = 2; notAssigned = 3; compliant = 4; remediated = 4; notApplicable = 5; unknown = 6 }
    $Worst = {
        param($States)
        @($States) | Sort-Object { $Rank[[string]$_] ?? 3 } | Select-Object -First 1
    }
    $ContextName = {
        param($Row)
        if ($Row.userPrincipalName) { [string]$Row.userPrincipalName } else { 'System account' }
    }
    $Errors = [System.Collections.Generic.List[string]]::new()
    $Results = [System.Collections.Generic.List[object]]::new()

    $Rows = @(New-GraphGetRequest -uri $Base -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id })

    foreach ($Group in ($Rows | Group-Object -Property id)) {
        $First = $Group.Group[0]
        $State = [string](& $Worst @($Group.Group.state))
        $Settings = @()
        $SettingsError = $null

        if ($IncludeAllSettings -or $State -in $Failing) {
            try {
                $Raw = @(New-GraphGetRequest -uri "$Base/$($First.id)/settingStates" -tenantid $TenantFilter -ErrorAction Stop)
                $Settings = @(foreach ($SettingGroup in ($Raw | Where-Object { $_ } | Group-Object -Property { [string]($_.settingInstanceId ? $_.settingInstanceId : "$($_.settingName)|$($_.setting)") })) {
                        $Row = $SettingGroup.Group | Sort-Object { $Rank[[string]$_.state] ?? 3 } | Select-Object -First 1
                        if (-not $IncludeAllSettings -and [string]$Row.state -notin $Failing) { continue }
                        $Csp = if ([string]$Row.setting -match "Key='([^']+)'") { $Matches[1] } elseif ([string]$Row.setting -match '^\.?/(Device|User|Vendor)/') { [string]$Row.setting } else { $null }
                        [pscustomobject]@{
                            Setting          = [string]$Row.setting
                            SettingName      = [string]$Row.settingName
                            CspPath          = $Csp
                            State            = [string]$Row.state
                            ErrorCode        = $Row.errorCode
                            # Intune reports signed 32-bit HRESULTs; the hex form is the one Microsoft documents.
                            ErrorCodeHex     = if ($Row.errorCode) { '0x{0:X8}' -f ([int64]$Row.errorCode -band 4294967295) } else { $null }
                            ErrorDescription = if ($Row.errorDescription -and [string]$Row.errorDescription -ne '0') { [string]$Row.errorDescription } else { $null }
                            CurrentValue     = $Row.currentValue
                            Contexts         = @($SettingGroup.Group | ForEach-Object { & $ContextName $_ } | Sort-Object -Unique)
                        }
                    }) | Sort-Object { $Rank[$_.State] ?? 3 }, SettingName, Setting
            } catch {
                $SettingsError = $_.Exception.Message
                $Errors.Add("settingStates for '$($First.displayName)' could not be read: $SettingsError")
            }
        }

        $Results.Add([pscustomobject]@{
                PolicyId      = [string]$First.id
                PolicyName    = [string]$First.displayName
                PlatformType  = [string]$First.platformType
                Version       = $First.version
                SettingCount  = $First.settingCount
                State         = $State
                Contexts      = @($Group.Group | ForEach-Object { [pscustomobject]@{ UserPrincipalName = (& $ContextName $_); UserId = [string]$_.userId; State = [string]$_.state } } | Sort-Object UserPrincipalName)
                Settings      = @($Settings)
                SettingsError = $SettingsError
            })
    }

    [pscustomobject]@{
        Results = @($Results | Sort-Object { $Rank[$_.State] ?? 3 }, PolicyName)
        Errors  = @($Errors)
    }
}
