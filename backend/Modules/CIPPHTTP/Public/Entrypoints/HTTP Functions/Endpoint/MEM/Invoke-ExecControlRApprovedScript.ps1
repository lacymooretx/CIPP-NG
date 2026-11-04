function Invoke-ExecControlRApprovedScript {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    .SYNOPSIS
        Runs a named, approved, read-only ControlR script on an Intune-managed device
    .DESCRIPTION
        Action=List returns the approved scripts. Action=Run (POST, with tenantFilter, ScriptKey, and DeviceId or
        SerialNumber) resolves the Intune device to its ControlR device and starts the script. Action=Status (with RunId)
        returns the run and its output.

        Only the scripts named here can run, and only in the tenants named here. ControlR enforces its own allow-list and
        tenant limit as well. Adding a script needs Lacy's approval and a matching change in ControlR. Each run is logged
        as "CIPP integration". Aspendora fork addition.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $ApprovedScripts = @{
        CountSavedBrowserLogins = @{ Id = '7d8a6af6-7150-45c6-addd-4a89e4c5793c'; Name = 'Count saved browser logins (counts only)' }
        IdentifyCopilotInstall  = @{ Id = '3833ef03-9fa5-4034-952d-7e84db85973d'; Name = 'Identify Copilot install' }
    }
    $AllowedTenants = @('aspendora.com')

    $Respond = {
        param([int]$Status, $Body)
        [HttpResponseContext]@{ StatusCode = [HttpStatusCode]$Status; Body = $Body }
    }

    $Action = [string]($Request.Query.Action ?? $Request.Body.Action)
    switch ($Action) {
        'List' {
            $Results = @($ApprovedScripts.GetEnumerator() | Sort-Object Name | ForEach-Object { [pscustomobject]@{ ScriptKey = $_.Key; Name = $_.Value.Name } })
            return (& $Respond 200 @{ Results = $Results; AllowedTenants = $AllowedTenants })
        }
        'Status' {
            $RunId = [string]($Request.Query.RunId ?? $Request.Body.RunId)
            if ($RunId -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') {
                return (& $Respond 400 @{ Results = 'RunId must be a GUID.' })
            }
            $Run = Invoke-CippControlRIntegrationRequest -Method GET -Path "runs/$RunId"
            if ($Run.Status -ne 200) { return (& $Respond $Run.Status @{ Results = $Run.Message }) }
            return (& $Respond 200 @{ Results = $Run.Data })
        }
        'Run' {
            if ($Request.Method -and $Request.Method -ne 'POST') {
                return (& $Respond 405 @{ Results = 'Action=Run requires POST.' })
            }
            $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
            $ScriptKey = [string]($Request.Query.ScriptKey ?? $Request.Body.ScriptKey)
            $DeviceId = [string]($Request.Query.DeviceId ?? $Request.Body.DeviceId)
            $SerialNumber = [string]($Request.Query.SerialNumber ?? $Request.Body.SerialNumber)

            if ($TenantFilter -notin $AllowedTenants) {
                return (& $Respond 403 @{ Results = "Tenant '$TenantFilter' is not approved for ControlR scripts." })
            }
            if (-not $ApprovedScripts.ContainsKey($ScriptKey)) {
                return (& $Respond 403 @{ Results = "Script '$ScriptKey' is not approved." })
            }
            $Approved = $ApprovedScripts[$ScriptKey]

            try {
                $Resolved = Resolve-CIPPManagedDevice -TenantFilter $TenantFilter -DeviceId $DeviceId -SerialNumber $SerialNumber
            } catch {
                return (& $Respond 500 @{ Results = "Failed: $($_.Exception.Message)" })
            }
            if ($Resolved.Status -ne 'Found') {
                return (& $Respond ([int]$Resolved.HttpStatus) @{ Results = $Resolved.Message; Candidates = @($Resolved.Candidates) })
            }

            $Match = Invoke-CippControlRIntegrationRequest -Method POST -Path 'resolve' -Body @{ intuneManagedDeviceId = $Resolved.Device.ManagedDeviceId }
            if ($Match.Status -ne 200) {
                return (& $Respond $Match.Status @{ Results = "No ControlR device found for $($Resolved.Device.DeviceName). $($Match.Message)" })
            }
            if ($Match.Data.cippTenantId -ne $TenantFilter -or [string]$Match.Data.intuneManagedDeviceId -ne [string]$Resolved.Device.ManagedDeviceId) {
                return (& $Respond 409 @{ Results = "ControlR's match for $($Resolved.Device.DeviceName) does not agree with this tenant and Intune device. Nothing was run." })
            }

            $Run = Invoke-CippControlRIntegrationRequest -Method POST -Path "devices/$($Match.Data.controlRDeviceId)/run/$($Approved.Id)"
            if ($Run.Status -ne 200) {
                Write-LogMessage -headers $Request.Headers -API 'ExecControlRApprovedScript' -tenant $TenantFilter -message "CIPP integration: ControlR refused '$($Approved.Name)' on $($Resolved.Device.DeviceName). $($Run.Message)" -Sev Error
                return (& $Respond $Run.Status @{ Results = "ControlR did not start the script. $($Run.Message)" })
            }

            Write-LogMessage -headers $Request.Headers -API 'ExecControlRApprovedScript' -tenant $TenantFilter -message "CIPP integration: started '$($Approved.Name)' on $($Resolved.Device.DeviceName), run $($Run.Data.runId)" -Sev Info
            return (& $Respond 200 @{
                    Results          = "Started '$($Approved.Name)' on $($Resolved.Device.DeviceName). Status: $($Run.Data.status)."
                    RunId            = $Run.Data.runId
                    Status           = $Run.Data.status
                    Device           = $Resolved.Device.DeviceName
                    ControlRDeviceId = $Match.Data.controlRDeviceId
                    MatchMethod      = $Match.Data.matchMethod
                })
        }
        default {
            return (& $Respond 400 @{ Results = 'Action must be List, Run or Status.' })
        }
    }
}
