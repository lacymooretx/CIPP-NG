function Start-VendorAccessReportTimer {
    <#
    .SYNOPSIS
    Hourly check that sends the weekly Vendor Access email on Mondays at 07:00 US Central (Aspendora fork)
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ($PSCmdlet.ShouldProcess('Start-VendorAccessReportTimer', 'Checking whether the weekly vendor access email is due')) {
        $PlaceholderPattern = '^(LongApplicationId|AppSecret|RefreshToken|tenantId)$'
        if (-not $env:ApplicationID -or $env:ApplicationID -match $PlaceholderPattern) { return }
        try {
            $Status = Invoke-CIPPVendorAccessWeekly
            Write-Information "Vendor access weekly: $Status"
        } catch {
            Write-LogMessage -API 'VendorAccess' -tenant 'Global' -message "Vendor access timer failed: $($_.Exception.Message)" -Sev 'Error' -LogData (Get-CippException -Exception $_)
        }
    }
}
