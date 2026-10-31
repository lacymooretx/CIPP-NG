function Test-CIPPEwsStatus {
    <#
    .SYNOPSIS
        Findings for a tenant's Exchange Web Services (EWS) state. Pure rules, no I/O.
    .DESCRIPTION
        Microsoft is switching EWS off in Exchange Online. A tenant whose EwsEnabled is unset ($null) gets flipped to
        $false during the rollout, and EWS stops within about an hour. Anything still using EWS (backup, email security,
        the iOS Mail app's Exchange account) then fails silently. EWS is removed for good in 2027, so the consumers need
        moving to Graph before then.
        Aspendora fork addition (Vikunja CIPP-29).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # Get-OrganizationConfig EwsEnabled: $true, $false or $null (unset).
        $EwsEnabled,
        # Names of apps granted full_access_as_app (application) on Exchange Online.
        [string[]]$AppOnlyConsumers = @(),
        # Names of apps granted the delegated EWS.AccessAsUser.All scope.
        [string[]]$DelegatedConsumers = @(),
        # Optional: hashtable "client|app" -> count of EWS mailbox reads seen in the audit log. $null = not checked.
        $RecentUsage
    )
    $Findings = [System.Collections.Generic.List[object]]::new()
    $Consumers = @(@($AppOnlyConsumers) + @($DelegatedConsumers) | Where-Object { $_ } | Sort-Object -Unique)
    $List = if ($Consumers) { $Consumers -join ', ' } else { 'none' }
    $State = if ($EwsEnabled -eq $true) { 'True' } elseif ($EwsEnabled -eq $false) { 'False' } else { 'unset' }

    if ($EwsEnabled -eq $false -and $Consumers) {
        $Findings.Add([pscustomobject]@{ Key = 'EwsDisabled'; Severity = 'Error'; Message = "EWS is OFF (EwsEnabled = False) but $($Consumers.Count) app(s) have EWS permissions: $List. Any of them still using EWS (backups, email security, iOS Mail) is failing now."; Fix = 'If something broke, run Set-OrganizationConfig -EwsEnabled $true (or ListEwsStatus Action=Pin); it takes about an hour to apply. Then move those apps to Graph before the 2027 removal.' })
    } elseif ($null -eq $EwsEnabled -and $Consumers) {
        $Findings.Add([pscustomobject]@{ Key = 'EwsUnset'; Severity = 'Warning'; Message = "EwsEnabled is unset, which Microsoft's rollout flips to False, cutting EWS off within about an hour. $($Consumers.Count) app(s) have EWS permissions: $List."; Fix = 'Pin it with Set-OrganizationConfig -EwsEnabled $true until those apps are confirmed on Graph.' })
    } elseif ($EwsEnabled -eq $true -and -not $Consumers) {
        $Findings.Add([pscustomobject]@{ Key = 'EwsUnneeded'; Severity = 'Info'; Message = 'EWS is pinned on, but no app has EWS permissions. It is attack surface with no user.'; Fix = 'Consider Set-OrganizationConfig -EwsEnabled $false after checking with the client.' })
    }
    if ($null -ne $RecentUsage -and $Consumers -and $EwsEnabled -ne $false) {
        $Used = @($RecentUsage.Keys | Where-Object { $RecentUsage[$_] -gt 0 })
        $Findings.Add([pscustomobject]@{ Key = 'EwsUsage'; Severity = 'Info'; Message = $(if ($Used) { "EWS mailbox reads in the last 7 days: $(($Used | ForEach-Object { "$_ ($($RecentUsage[$_]))" }) -join '; ')." } else { 'No EWS mailbox reads in the last 7 days. The apps above may already use Graph, or may only run occasionally; confirm with each vendor before turning EWS off.' }); Fix = 'Plan the move off EWS before the 2027 removal.' })
    }
    [pscustomobject]@{ EwsEnabled = $State; Consumers = $Consumers; Findings = @($Findings) }
}
