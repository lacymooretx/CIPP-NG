function Get-CIPPAlertIntuneEnrollmentFailures {
    <#
    .SYNOPSIS
        Alert on Intune enrollment failures
    .DESCRIPTION
        Reads beta deviceManagement/troubleshootingEvents (the Intune enrollment failure log; verified to work with
        CIPP's delegated token and to honour an eventDateTime filter, 2026-10-31) for the last
        EnrollmentFailureLookbackHours (default 24) and raises the enrollmentTroubleshootingEvent entries.
        Repeated attempts are grouped: one row per device (or user, when Intune has no device id), failure reason and
        day, carrying the attempt count, Intune's own failure text and its suggested remediation.
        Event mode (Write-AlertTrace -Append): each group notifies once and is never "resolved" by a quiet run.
        Report only. Aspendora fork addition (Vikunja CIPP-27).
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
    $Parsed = 0
    if ($null -ne $InputValue.EnrollmentFailureLookbackHours -and [int]::TryParse([string]$InputValue.EnrollmentFailureLookbackHours, [ref]$Parsed) -and $Parsed -gt 0) { $Hours = $Parsed }
    $Cutoff = [datetime]::UtcNow.AddHours(-$Hours).ToString('yyyy-MM-ddTHH:mm:ssZ')
    try {
        $Events = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/troubleshootingEvents?`$filter=eventDateTime ge $Cutoff" -tenantid $TenantFilter -ErrorAction Stop)
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Intune enrollment failures: could not read troubleshootingEvents: $((Get-CippException -Exception $_).NormalizedError)" -sev Warning
        return
    }
    $Empty = '00000000-0000-0000-0000-000000000000'
    $Failures = @($Events | Where-Object { $_.id -and [string]$_.'@odata.type' -match 'enrollmentTroubleshootingEvent' })
    if ($Failures.Count -eq 0) { return }

    $Groups = $Failures | Group-Object -Property {
        $Who = if ($_.deviceId -and $_.deviceId -ne $Empty) { "device:$($_.deviceId)" } elseif ($_.userId -and $_.userId -ne $Empty) { "user:$($_.userId)" } else { "event:$($_.correlationId ?? $_.id)" }
        $Day = if ($_.eventDateTime -is [datetime]) { ([datetime]$_.eventDateTime).ToUniversalTime().ToString('yyyy-MM-dd') } else { ([string]$_.eventDateTime).Substring(0, [math]::Min(10, ([string]$_.eventDateTime).Length)) }
        "$Who|$($_.failureReason)|$Day"
    }
    $Rows = foreach ($G in $Groups) {
        $Latest = @($G.Group | Sort-Object -Property eventDateTime -Descending)[0]
        $Detail = $Latest.troubleshootingErrorDetails
        [pscustomobject]@{
            Id              = "EnrollFail|$($G.Name)"
            When            = Format-CIPPCentralTime $Latest.eventDateTime
            Attempts        = $G.Count
            OS              = "$($Latest.operatingSystem) $($Latest.osVersion)".Trim()
            EnrollmentType  = [string]$Latest.enrollmentType
            FailureCategory = [string]$Latest.failureCategory
            FailureReason   = [string]$Latest.failureReason
            EntraDeviceId   = if ($Latest.deviceId -ne $Empty) { [string]$Latest.deviceId } else { '' }
            UserId          = if ($Latest.userId -ne $Empty) { [string]$Latest.userId } else { '' }
            Remediation     = [string]$Detail.remediation
            Message         = "Intune enrollment failed$(if ($G.Count -gt 1) { " $($G.Count) times" }) ($($Latest.enrollmentType), $($Latest.failureReason)): $([string]($Detail.failureDetails ?? $Detail.failure))"
        }
    }
    @(Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows) -Append | Where-Object { $_ })
}
