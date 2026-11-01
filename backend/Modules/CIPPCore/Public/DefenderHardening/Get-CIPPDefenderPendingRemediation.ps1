function Get-CIPPDefenderPendingRemediation {
    <#
    .SYNOPSIS
        Defender automated investigation remediations waiting for approval in one tenant (MDO and MDE).
    .DESCRIPTION
        Read-only. Lists unresolved security alerts_v2 created in the last LookbackDays (app token,
        SecurityAlert.Read.All), keeps those with investigationState 'pendingApproval'
        (Select-CIPPPendingRemediationAlerts), then reads each pending alert once more for its evidence to count
        the actions awaiting approval.
        A pending email remediation is the visible symptom of MDO automation not set to auto-remediate: with
        "Soft delete" automation for similar files / similar URLs on, AIR applies the action itself. That
        automation setting is portal-only (Defender portal > Settings > Email & collaboration > MDO automation
        settings); no EXO / Security & Compliance cmdlet or Graph API exposes it, so it is reported as Manual.
        Returns @{ Tenant; PendingCount; OverThresholdCount; Alerts; AutomationSetting; Notes }.
        Aspendora fork addition (Vikunja CIPP-31).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [int]$LookbackDays = 90,
        [int]$MinAgeHours = 24,
        [ValidateSet('All', 'MDO', 'MDE')][string]$Source = 'All'
    )
    $Since = [datetime]::UtcNow.AddDays(-$LookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $Filter = "status ne 'resolved' and createdDateTime ge $Since"
    switch ($Source) {
        'MDO' { $Filter += " and serviceSource eq 'microsoftDefenderForOffice365'" }
        'MDE' { $Filter += " and serviceSource eq 'microsoftDefenderForEndpoint'" }
    }
    $Select = 'id,title,status,severity,serviceSource,createdDateTime,lastUpdateDateTime,incidentId,incidentWebUrl,investigationState'
    $Uri = "https://graph.microsoft.com/beta/security/alerts_v2?`$filter=$([uri]::EscapeDataString($Filter))&`$select=$Select"
    $Alerts = @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -AsApp $true -ErrorAction Stop)
    $Pending = @(Select-CIPPPendingRemediationAlerts -Alerts $Alerts -MinAgeHours $MinAgeHours)
    $Notes = [System.Collections.Generic.List[string]]::new()

    if ($Pending.Count -gt 0) {
        try {
            $Requests = @($Pending | ForEach-Object { [pscustomobject]@{ id = $_.AlertId; method = 'GET'; url = "/security/alerts_v2/$($_.AlertId)" } })
            $Full = @{}
            foreach ($R in @(New-GraphBulkRequest -Requests $Requests -tenantid $TenantFilter -AsApp $true)) {
                if ($R.body.id) { $Full[[string]$R.id] = $R.body }
            }
            $Detailed = @(Select-CIPPPendingRemediationAlerts -Alerts @($Pending | ForEach-Object { $Full[$_.AlertId] } | Where-Object { $_ }) -MinAgeHours $MinAgeHours)
            # Keep alerts whose detail read failed, with PendingActions unknown.
            $Pending = @($Detailed) + @($Pending | Where-Object { -not $Full.ContainsKey($_.AlertId) })
        } catch {
            $Notes.Add("pending action counts could not be read: $((Get-CippException -Exception $_).NormalizedError)")
        }
    }

    $Central = try { [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { $null }
    foreach ($P in $Pending) {
        $Local = ''
        if ($Central -and $P.CreatedUtc) {
            try {
                $Utc = ([datetimeoffset]$P.CreatedUtc).UtcDateTime
                $L = [System.TimeZoneInfo]::ConvertTimeFromUtc($Utc, $Central)
                $Zone = if ($Central.IsDaylightSavingTime($L)) { 'CDT' } else { 'CST' }
                $Local = "$($L.ToString('yyyy-MM-dd HH:mm')) $Zone ($($Utc.ToString('HH:mm')) UTC)"
            } catch {}
        }
        $P | Add-Member -NotePropertyName Created -NotePropertyValue $Local -Force
    }

    [pscustomobject]@{
        Tenant             = $TenantFilter
        PendingCount       = $Pending.Count
        OverThresholdCount = @($Pending | Where-Object { $_.OverThreshold -eq $true }).Count
        MinAgeHours        = $MinAgeHours
        Alerts             = @($Pending | Sort-Object CreatedUtc)
        AutomationSetting  = [pscustomobject]@{
            State  = 'NotApiReachable'
            Status = 'Manual'
            Detail = 'MDO automated remediation (similar files / similar URLs -> Soft delete) is set in the Defender portal under Settings > Email & collaboration > MDO automation settings. No cmdlet or Graph API exposes it; verify by hand. Pending email approvals here mean it is not set to remediate automatically.'
        }
        Notes              = @($Notes)
    }
}
