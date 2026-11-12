function Start-BreakGlassProvisionTimer {
    <#
    .SYNOPSIS
    Daily break-glass detector (plans for Lacy to approve; creates nothing) and, on Mondays, the weekly
    Microsoft 365 admin inventory to Hudu. Aspendora fork, onboarding Phase 3 (2026-11-12).
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if ($PSCmdlet.ShouldProcess('Start-BreakGlassProvisionTimer', 'Break-glass detector and admin inventory')) {
        $PlaceholderPattern = '^(LongApplicationId|AppSecret|RefreshToken|tenantId)$'
        if (-not $env:ApplicationID -or $env:ApplicationID -match $PlaceholderPattern) { return }
        try {
            $Plans = Invoke-CIPPBreakGlassDetector
            Write-Information "Break-glass detector: $(@($Plans).Count) tenant(s) below the standard"
        } catch {
            Write-LogMessage -API 'BreakGlassProvision' -tenant 'Global' -message "Break-glass detector failed: $($_.Exception.Message)" -Sev 'Error' -LogData (Get-CippException -Exception $_)
        }
        try {
            $Pending = @(Invoke-CIPPBreakGlassKeeperHandoff)
            if ($Pending.Count) { Write-Information "Break-glass hand-off: $(($Pending | Group-Object Status | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', ')" }
        } catch {
            Write-LogMessage -API 'BreakGlassProvision' -tenant 'Global' -message "Break-glass Keeper hand-off retry failed: $($_.Exception.Message)" -Sev 'Error' -LogData (Get-CippException -Exception $_)
        }
        $Tz = try { [TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { [TimeZoneInfo]::FindSystemTimeZoneById('Central Standard Time') }
        if ([TimeZoneInfo]::ConvertTimeFromUtc((Get-Date).ToUniversalTime(), $Tz).DayOfWeek -eq 'Monday') {
            try { $null = Invoke-CIPPAdminInventorySync }
            catch { Write-LogMessage -API 'AdminInventory' -tenant 'Global' -message "Admin inventory failed: $($_.Exception.Message)" -Sev 'Error' -LogData (Get-CippException -Exception $_) }
        }
    }
}
