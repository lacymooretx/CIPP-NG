Function Invoke-ListDefenderState {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Lists Microsoft Defender antivirus state and detected threats for Intune-managed devices in a tenant.

        IncludeMalware=true additionally expands detectedMalwareState, the per-device malware detail
        underneath windowsProtectionState: what was found, its severity, its execution state and
        whether it was actually remediated. The state alone says "Defender is healthy"; this says
        whether anything was caught and what happened to it.

        It is a NESTED expand on the same request, not a per-device fan-out - verified honoured
        against live Graph rather than assumed, since Graph silently ignores expands it does not
        support. Off by default so the existing lighter query is unchanged for callers that only
        want protection state.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $StatusCode = [HttpStatusCode]::OK

    # Interact with query parameters or the body of the request.
    $TenantFilter = $Request.Query.TenantFilter
    $DeviceID = $Request.Query.DeviceID
    $IncludeMalware = $Request.Query.IncludeMalware -eq $true

    # A nested expand costs nothing extra in round trips but returns a lot more per device, so it
    # is opt-in rather than always on.
    $Expand = if ($IncludeMalware) { 'windowsProtectionState($expand=detectedMalwareState)' } else { 'windowsProtectionState' }

    try {
        # If DeviceID is provided, get Defender state for that specific device
        if ($DeviceID) {
            $GraphRequest = New-GraphGetRequest -tenantid $TenantFilter -uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($DeviceID)?`$expand=$Expand&`$select=id,deviceName,deviceType,operatingSystem,windowsProtectionState"
        }
        # If no DeviceID is provided, get Defender state for all devices
        else {
            $GraphRequest = New-GraphGetRequest -tenantid $TenantFilter -uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$expand=$Expand&`$select=id,deviceName,deviceType,operatingSystem,windowsProtectionState"
        }

        # Ensure we return an array even if single device
        if ($GraphRequest -and -not ($GraphRequest -is [array])) {
            $GraphRequest = @($GraphRequest)
        }

        if ($IncludeMalware) {
            # Summarise the malware detail so a list view does not have to walk the nested
            # collection itself. ACTIVE malware is counted separately from merely detected: an
            # entry that was cleaned or quarantined is history, one still executing is an incident.
            foreach ($Device in $GraphRequest) {
                $Malware = @($Device.windowsProtectionState.detectedMalwareState)
                $Active = @($Malware | Where-Object { $_.executionState -in @('running', 'blocked', 'suspended') -or $_.state -in @('detected', 'actionFailed') })
                $Device | Add-Member -NotePropertyName 'MalwareCount' -NotePropertyValue $Malware.Count -Force
                $Device | Add-Member -NotePropertyName 'ActiveMalwareCount' -NotePropertyValue $Active.Count -Force
                $Device | Add-Member -NotePropertyName 'MalwareNames' -NotePropertyValue (($Malware.displayName | Where-Object { $_ } | Sort-Object -Unique) -join ', ') -Force
                $Device | Add-Member -NotePropertyName 'HighestMalwareSeverity' -NotePropertyValue (
                    @('severe', 'high', 'moderate', 'low') | Where-Object { $sev = $_; @($Malware | Where-Object { $_.severity -eq $sev }).Count -gt 0 } | Select-Object -First 1
                ) -Force
            }
        }

        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        $StatusCode = [HttpStatusCode]::OK
        $GraphRequest = "$($ErrorMessage)"
    }
    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @($GraphRequest)
        })

}
