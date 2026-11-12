function Start-BreakGlassApprovalPollTimer {
    <#
    .SYNOPSIS
    Every 10 minutes: pull approved break-glass change requests from ControlR and run them (Aspendora fork, ONB-13).
    One GET when nothing is approved. Respects the kill switch and ApprovalSource.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if ($PSCmdlet.ShouldProcess('Start-BreakGlassApprovalPollTimer', 'Poll ControlR for approved break-glass plans')) {
        $PlaceholderPattern = '^(LongApplicationId|AppSecret|RefreshToken|tenantId)$'
        if (-not $env:ApplicationID -or $env:ApplicationID -match $PlaceholderPattern) { return }
        try {
            $Done = @(Invoke-CIPPBreakGlassApprovalPoll)
            if ($Done.Count) { Write-Information "Break-glass approval poll: $(($Done | ForEach-Object { "$($_.Tenant) $($_.Result)" }) -join ', ')" }
        } catch {
            Write-LogMessage -API 'BreakGlassProvision' -tenant 'Global' -message "Break-glass approval poll failed: $($_.Exception.Message)" -Sev 'Error' -LogData (Get-CippException -Exception $_)
        }
    }
}
