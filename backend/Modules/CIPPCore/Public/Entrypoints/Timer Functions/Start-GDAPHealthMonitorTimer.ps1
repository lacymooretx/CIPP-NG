function Start-GDAPHealthMonitorTimer {
    <#
    .SYNOPSIS
    Daily GDAP relationship, partner token and SAM credential health check (Aspendora fork, Vikunja CIPP-2)
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ($PSCmdlet.ShouldProcess('Start-GDAPHealthMonitorTimer', 'Checking GDAP and token health')) {
        $PlaceholderPattern = '^(LongApplicationId|AppSecret|RefreshToken|tenantId)$'
        if (-not $env:ApplicationID -or $env:ApplicationID -match $PlaceholderPattern) { return }
        try {
            $Report = Invoke-CIPPGDAPHealthCheck
            Write-Information "GDAP health: $($Report.Summary.Errors) error(s), $($Report.Summary.Warnings) warning(s), $(@($Report.Alerted).Count) alerted"
        } catch {
            Write-LogMessage -API 'GDAP Health' -tenant 'Global' -message "GDAP health check failed: $($_.Exception.Message)" -Sev 'Error' -LogData (Get-CippException -Exception $_)
        }
    }
}
