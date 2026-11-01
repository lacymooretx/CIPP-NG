function Get-CIPPAlertDefenderPendingRemediation {
    <#
    .SYNOPSIS
        Defender automated investigations waiting more than a day for remediation approval
    .DESCRIPTION
        Raises every Defender alert whose automated investigation (AIR) has been in 'pendingApproval' for at
        least PendingRemediationHours (default 24), measured from the alert's creation time. Email
        remediations (MDO) sitting here mean MDO automation is not soft-deleting similar messages on its own;
        device remediations (MDE) mean the device group automation level requires approval.
        State mode: rows carry Id 'PendingApproval|<alert id>', so each alert notifies once and resolves when it
        is approved, rejected or the alert is resolved. A run that cannot list alerts reports nothing.
        Report only. Aspendora fork addition (Vikunja CIPP-31).
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        [Parameter(Mandatory)]
        $TenantFilter
    )
    $Hours = 24
    # The value arrives either bare or as { PendingRemediationHours = n }, depending on how the alert was saved.
    $Raw = $InputValue
    if ($InputValue -is [System.Collections.IDictionary]) {
        $Raw = $InputValue['PendingRemediationHours']
    } elseif ($null -ne $InputValue -and $InputValue.PSObject.Properties['PendingRemediationHours']) {
        $Raw = $InputValue.PendingRemediationHours
    }
    $Parsed = 0
    if ($null -ne $Raw -and [int]::TryParse([string]$Raw, [ref]$Parsed) -and $Parsed -gt 0) { $Hours = $Parsed }
    try {
        $Report = Get-CIPPDefenderPendingRemediation -TenantFilter $TenantFilter -MinAgeHours $Hours
        $Rows = @($Report.Alerts | Where-Object { $_.OverThreshold -eq $true } | ForEach-Object {
                $Kind = if ($_.ServiceSource -eq 'microsoftDefenderForOffice365') { 'email (MDO)' } elseif ($_.ServiceSource -eq 'microsoftDefenderForEndpoint') { 'device (MDE)' } else { $_.ServiceSource }
                $Actions = if ($null -ne $_.PendingActions) { "$($_.PendingActions) action(s)" } else { 'actions' }
                [pscustomobject]@{
                    Message        = "Defender $Kind remediation awaiting approval for $([math]::Floor($_.AgeHours))h+: '$($_.Title)' (incident $($_.IncidentId)). Approve or reject $Actions in Action Center."
                    Title          = $_.Title
                    Source         = $Kind
                    IncidentId     = $_.IncidentId
                    Created        = $_.Created
                    AgeHours       = $_.AgeHours
                    PendingActions = $_.PendingActions
                    IncidentUrl    = $_.IncidentUrl
                    Id             = "PendingApproval|$($_.AlertId)"
                }
            })
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows
    } catch {
        $Err = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Defender pending remediation check failed: $($Err.NormalizedError)" -sev (Get-CIPPAlertFailureSeverity -ErrorText "$((Get-CippException -Exception $_).NormalizedError) $_") -LogData $Err
    }
}
