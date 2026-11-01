function Select-CIPPPendingRemediationAlerts {
    <#
    .SYNOPSIS
        Picks the Defender alerts whose automated investigation is waiting for an admin to approve remediation.
    .DESCRIPTION
        Pure. Alerts are Graph security alerts_v2 objects. An alert counts when investigationState is
        'pendingApproval' (the Action Center "Pending" tab). Graph cannot $filter on investigationState, so the
        caller lists unresolved alerts and this filters client-side.
        AgeHours is measured from createdDateTime: Graph does not say when the investigation entered
        pendingApproval, so the age is an upper bound on how long it has been waiting. OverThreshold is
        AgeHours >= MinAgeHours.
        PendingActions counts evidence items with remediationStatus 'pendingApproval' when the alert carries
        evidence (the list call may omit it); $null means not known.
        Aspendora fork addition (Vikunja CIPP-31).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [object[]]$Alerts = @(),
        [datetime]$Now = [datetime]::UtcNow,
        [int]$MinAgeHours = 24
    )
    foreach ($A in @($Alerts)) {
        if ($null -eq $A -or [string]$A.investigationState -ne 'pendingApproval') { continue }
        if ([string]$A.status -eq 'resolved') { continue }
        $Created = $null
        try { $Created = ([datetimeoffset]$A.createdDateTime).UtcDateTime } catch {}
        $Age = if ($Created) { [math]::Round(($Now.ToUniversalTime() - $Created).TotalHours, 1) } else { $null }
        $Pending = $null
        if ($null -ne $A.evidence) {
            $Pending = @(@($A.evidence) | Where-Object { [string]$_.remediationStatus -eq 'pendingApproval' }).Count
        }
        [pscustomobject]@{
            AlertId        = [string]$A.id
            IncidentId     = [string]$A.incidentId
            Title          = ([string]$A.title -replace '[​﻿]', '').Trim()
            ServiceSource  = [string]$A.serviceSource
            Status         = [string]$A.status
            Severity       = [string]$A.severity
            CreatedUtc     = if ($Created) { $Created.ToString('o') } else { [string]$A.createdDateTime }
            AgeHours       = $Age
            OverThreshold  = ($null -ne $Age -and $Age -ge $MinAgeHours)
            PendingActions = $Pending
            IncidentUrl    = [string]$A.incidentWebUrl
        }
    }
}
