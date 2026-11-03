function Invoke-ListDeviceConfigurationState {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .SYNOPSIS
        Configuration profile assignment and state for one device
    .DESCRIPTION
        For one device (DeviceId: Intune managed device id or Entra deviceId, or SerialNumber), lists the configuration
        profiles Intune reports state for, one row per profile with its worst state across user and system contexts,
        and for failing profiles the failing settings: CSP path, state, error code and description. IncludeSettings=true
        returns every setting of every profile (one extra Graph read per profile).

        Unless IncludeAssignments=false, each row also carries its type and assignment from the effective-policy
        evaluation, and profiles that target the device but have no state are added with State 'notReported'. Graph's
        device state collections do not cover Settings Catalog, Endpoint Security or update profiles, so 'notReported'
        means Graph gave no answer, not that the profile is healthy.

        A device that cannot be resolved is a 400, 404 or 409. A failed state read is a 500, never an empty list; partial
        failures set Partial and list the Errors. Report only: nothing is changed. Aspendora fork addition.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    $DeviceId = [string]($Request.Query.DeviceId ?? $Request.Body.DeviceId)
    $SerialNumber = [string]($Request.Query.SerialNumber ?? $Request.Body.SerialNumber)
    $IncludeSettings = $Request.Query.IncludeSettings -eq $true -or $Request.Body.IncludeSettings -eq $true
    $IncludeAssignments = $Request.Query.IncludeAssignments -ne $false -and $Request.Body.IncludeAssignments -ne $false

    try {
        $Resolved = Resolve-CIPPManagedDevice -TenantFilter $TenantFilter -DeviceId $DeviceId -SerialNumber $SerialNumber
        if ($Resolved.Status -ne 'Found') {
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]$Resolved.HttpStatus; Body = @{ Results = $Resolved.Message; Candidates = @($Resolved.Candidates); Detail = $Resolved.Detail } })
        }

        $States = Get-CIPPManagedDevicePolicyStates -TenantFilter $TenantFilter -ManagedDeviceId $Resolved.Device.ManagedDeviceId -Collection 'deviceConfigurationStates' -IncludeAllSettings:$IncludeSettings
        $Errors = [System.Collections.Generic.List[string]]::new()
        foreach ($E in @($States.Errors)) { $Errors.Add([string]$E) }
        $Notes = [System.Collections.Generic.List[string]]::new()

        # Apps and compliance policies have their own views; everything else that lands on a device is a profile.
        $Assignments = @{}
        if ($IncludeAssignments) {
            try {
                $Effective = Get-CIPPIntuneEffectivePolicy -TenantFilter $TenantFilter -DeviceId $Resolved.Device.ManagedDeviceId
                foreach ($Row in @($Effective.Results | Where-Object { $_.Family -notin @('MobileApps', 'deviceCompliancePolicies') })) { $Assignments[[string]$Row.PolicyId] = $Row }
                foreach ($E in @($Effective.Errors)) { $Errors.Add("Assignment evaluation: $E") }
            } catch {
                $Errors.Add("Assignment evaluation failed, so Type and Assignment are blank and profiles with no state are not listed: $((Get-CippException -Exception $_).NormalizedError)")
            }
        } else {
            $Notes.Add('IncludeAssignments=false: Type and Assignment are blank and profiles with no device state are not listed.')
        }

        $ToAssignment = {
            param($Row)
            if (-not $Row) { return $null }
            [pscustomobject]@{
                Status = $Row.Status; Applies = $Row.Applies; TargetedVia = $Row.TargetedVia; Filter = $Row.Filter
                FilterMode = $Row.FilterMode; FilterResult = $Row.FilterResult; ExcludedBy = $Row.ExcludedBy; Notes = $Row.Notes
            }
        }

        $Results = [System.Collections.Generic.List[object]]::new()
        foreach ($Row in @($States.Results)) {
            $Assignment = $Assignments[$Row.PolicyId]
            $Results.Add([pscustomobject]@{
                    PolicyId = $Row.PolicyId; PolicyName = $Row.PolicyName; Type = $Assignment.PolicyType; PlatformType = $Row.PlatformType
                    Version = $Row.Version; SettingCount = $Row.SettingCount; State = $Row.State; StateSource = 'deviceConfigurationStates'
                    Contexts = @($Row.Contexts); Settings = @($Row.Settings); SettingsError = $Row.SettingsError; Assignment = (& $ToAssignment $Assignment)
                })
        }
        $Reported = @($States.Results.PolicyId)
        foreach ($Id in @($Assignments.Keys | Where-Object { $_ -notin $Reported })) {
            $Assignment = $Assignments[$Id]
            $Results.Add([pscustomobject]@{
                    PolicyId = $Assignment.PolicyId; PolicyName = $Assignment.PolicyName; Type = $Assignment.PolicyType; PlatformType = $Assignment.Platform
                    Version = $null; SettingCount = $null; State = 'notReported'; StateSource = $null
                    Contexts = @(); Settings = @(); SettingsError = $null; Assignment = (& $ToAssignment $Assignment)
                })
        }
        # Only profiles the evaluation says apply: an excluded or filtered-out profile with no state is expected.
        $NotReported = @($Results | Where-Object { $_.State -eq 'notReported' -and $_.Assignment.Applies -eq $true }).Count
        if ($NotReported -gt 0) { $Notes.Add("$NotReported profile(s) apply to this device but Graph's device state collections have no row for them (Settings Catalog, Endpoint Security and update profiles). Their state is unknown, not healthy.") }

        $Body = @{
            Device  = $Resolved.Device
            Results = @($Results)
            Summary = @{
                Profiles     = $Results.Count
                Failing      = @($Results | Where-Object State -In @('error', 'conflict', 'nonCompliant')).Count
                NotReported  = $NotReported
                ByState      = @($Results | Group-Object State | Sort-Object Name | ForEach-Object { [pscustomobject]@{ State = $_.Name; Count = $_.Count } })
            }
            Partial = $Errors.Count -gt 0
            Errors  = @($Errors)
            Notes   = @($Notes)
        }
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Body })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $Request.Params.CIPPEndpoint -tenant $TenantFilter -message "Device configuration state lookup failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $($ErrorMessage.NormalizedError)" } })
    }
}
