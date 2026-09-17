function Invoke-ListDevicePolicyConflicts {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Surfaces the conflict state Intune actually computed for a device, rather than diffing
        policies against each other (which is what ExecCompareIntunePolicy does, and is a different
        question).

        Three signals, in descending order of certainty:
          1. Intune reported the setting as 'conflict' - its own computed verdict, not ours.
          2. The setting state carries more than one entry in 'sources', i.e. Intune itself records
             more than one policy claiming that setting.
          3. The same setting key appears under more than one policy across the device's policy
             states. This catches the case where each policy individually reports success but two
             of them are writing the same CSP path, which is a conflict waiting to surface.
        Settings reported as 'error' are returned too, since "the setting failed" is the same
        question an operator is asking when they open this view.

        NOT built on deviceConfigurationConflictSummary. That tenant-wide endpoint was tested
        against four tenants on 2026-09-17 and returned HTTP 500 on two of them and an empty
        collection on the other two - it produced usable data on none. It is still queried, as a
        best-effort extra, but a failure there is reported and never allowed to fail the request.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Query.TenantFilter ?? $Request.Body.TenantFilter
    $DeviceId = $Request.Query.DeviceId ?? $Request.Body.DeviceId

    if (-not $TenantFilter -or -not $DeviceId) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'TenantFilter and DeviceId are both required.' } })
    }

    $GraphBeta = 'https://graph.microsoft.com/beta'

    try {
        # Both collections matter: a device can be non-compliant from a compliance policy and
        # misconfigured from a configuration profile, and an operator asking "what is wrong with
        # this device" means both.
        $Collections = @(
            @{ Name = 'deviceConfigurationStates'; Label = 'Configuration' }
            @{ Name = 'deviceCompliancePolicyStates'; Label = 'Compliance' }
        )

        # setting key -> list of observations across every policy on the device
        $BySetting = @{}
        $PolicyCount = 0

        foreach ($Collection in $Collections) {
            $States = @()
            try {
                $States = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/managedDevices/$DeviceId/$($Collection.Name)" -tenantid $TenantFilter)
            } catch {
                Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Device policy conflicts: could not read $($Collection.Name) for $DeviceId." -Sev 'Info'
                continue
            }

            foreach ($State in $States) {
                if (-not $State.id) { continue }
                $PolicyCount++
                $PolicyName = [string]$State.displayName

                $SettingStates = @()
                try {
                    $SettingStates = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/managedDevices/$DeviceId/$($Collection.Name)/$($State.id)/settingStates" -tenantid $TenantFilter)
                } catch {
                    # One unreadable policy must not discard the others.
                    continue
                }

                foreach ($Setting in $SettingStates) {
                    # 'setting' is the CSP path and is what actually collides; settingName is a type
                    # label ("Windows10CustomConfiguration") and is far too coarse to group on.
                    $Key = [string]($Setting.setting ?? $Setting.settingInstanceId ?? $Setting.instanceDisplayName)
                    if (-not $Key) { continue }
                    if (-not $BySetting.ContainsKey($Key)) { $BySetting[$Key] = [System.Collections.Generic.List[object]]::new() }
                    $BySetting[$Key].Add([PSCustomObject]@{
                            PolicyName   = $PolicyName
                            PolicyId     = [string]$State.id
                            Scope        = $Collection.Label
                            State        = [string]$Setting.state
                            CurrentValue = $Setting.currentValue
                            ErrorCode    = $Setting.errorCode
                            ErrorDetail  = [string]$Setting.errorDescription
                            DisplayName  = [string]$Setting.instanceDisplayName
                            Sources      = @($Setting.sources)
                        })
                }
            }
        }

        $Findings = [System.Collections.Generic.List[object]]::new()

        foreach ($Key in $BySetting.Keys) {
            $Observations = @($BySetting[$Key])
            $DistinctPolicies = @($Observations.PolicyId | Sort-Object -Unique)
            $ConflictStates = @($Observations | Where-Object { $_.State -eq 'conflict' })
            $ErrorStates = @($Observations | Where-Object { $_.State -eq 'error' })
            # Intune's own record of multiple owners for one setting.
            $MultiSource = @($Observations | Where-Object { @($_.Sources).Count -gt 1 })

            $Reasons = [System.Collections.Generic.List[string]]::new()
            if ($ConflictStates.Count -gt 0) { $Reasons.Add('Intune reported a conflict') }
            if ($MultiSource.Count -gt 0) { $Reasons.Add('Multiple policies claim this setting') }
            if ($DistinctPolicies.Count -gt 1) { $Reasons.Add("Setting appears in $($DistinctPolicies.Count) policies") }
            if ($ErrorStates.Count -gt 0) { $Reasons.Add('Setting failed to apply') }
            if ($Reasons.Count -eq 0) { continue }

            $Severity = if ($ConflictStates.Count -gt 0) { 'Conflict' }
                        elseif ($DistinctPolicies.Count -gt 1 -or $MultiSource.Count -gt 0) { 'Contested' }
                        else { 'Error' }

            $Findings.Add([PSCustomObject]@{
                    Setting      = $Key
                    DisplayName  = ($Observations.DisplayName | Where-Object { $_ } | Select-Object -First 1)
                    Severity     = $Severity
                    Reasons      = ($Reasons -join '; ')
                    Policies     = (($Observations | ForEach-Object { "$($_.PolicyName) [$($_.Scope)] = $($_.State)" } | Sort-Object -Unique) -join ' | ')
                    PolicyCount  = $DistinctPolicies.Count
                    CurrentValue = ($Observations.CurrentValue | Where-Object { $null -ne $_ } | Select-Object -First 1)
                    ErrorDetail  = ($Observations.ErrorDetail | Where-Object { $_ -and $_ -ne '0' } | Select-Object -First 1)
                })
        }

        # Best-effort only. This endpoint 500s on real tenants; it must never fail the request.
        $TenantSummary = $null
        $TenantSummaryError = $null
        try {
            $TenantSummary = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/deviceConfigurationConflictSummary" -tenantid $TenantFilter)
        } catch {
            $TenantSummaryError = 'deviceConfigurationConflictSummary is unavailable for this tenant (Microsoft returns an internal server error on some tenants).'
        }

        $Order = @{ Conflict = 0; Contested = 1; Error = 2 }
        $Body = @{
            Results  = @($Findings | Sort-Object @{ Expression = { $Order[$_.Severity] } }, Setting)
            Metadata = @{
                DeviceId            = $DeviceId
                PoliciesInspected   = $PolicyCount
                SettingsInspected   = $BySetting.Keys.Count
                ConflictCount       = @($Findings | Where-Object { $_.Severity -eq 'Conflict' }).Count
                ContestedCount      = @($Findings | Where-Object { $_.Severity -eq 'Contested' }).Count
                ErrorCount          = @($Findings | Where-Object { $_.Severity -eq 'Error' }).Count
                TenantConflictSummary = $TenantSummary
                TenantSummaryError    = $TenantSummaryError
            }
        }
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Device policy conflict lookup failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $Body = @{ Results = "Failed to resolve policy conflicts: $($ErrorMessage.NormalizedError)" }
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
