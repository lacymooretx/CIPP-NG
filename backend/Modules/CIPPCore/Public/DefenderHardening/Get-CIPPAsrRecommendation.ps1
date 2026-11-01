function Get-CIPPAsrRecommendation {
    <#
    .SYNOPSIS
        Audit-to-block recommendation for one ASR rule.
    .DESCRIPTION
        Pure. Mode is the rule's effective mode (Resolve-CIPPAsrRuleModes). Evidence is the tenant evidence summary
        (Get-CIPPAsrEvidence: Available, Source, CoverageDays, DevicesReporting) and RuleEvidence the rule's counts
        (Audited, Blocked, Warned, Devices) or $null when the rule had no hits.
        "Ready for block" needs proof that the rule was quiet: an evidence source that covers the whole window with
        at least one reporting device. No evidence is never read as no hits.
        Returns @{ Recommendation; Reason }. Recommendation is one of ReadyForBlock, KeepAudit, AlreadyBlock,
        NotConfigured, FixConflict. Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [string]$Mode,
        $Evidence,
        $RuleEvidence,
        [int]$WindowDays = 14
    )
    $Audited = [int]($RuleEvidence.Audited ?? 0)
    $Blocked = [int]($RuleEvidence.Blocked ?? 0)
    $Warned = [int]($RuleEvidence.Warned ?? 0)
    $Devices = [int]($RuleEvidence.Devices ?? 0)
    $Reporting = [int]($Evidence.DevicesReporting ?? 0)
    $Coverage = [int]($Evidence.CoverageDays ?? 0)
    $Out = { param($R, $Why) [pscustomobject]@{ Recommendation = $R; Reason = $Why } }

    switch ($Mode) {
        'Conflict' { return (& $Out 'FixConflict' 'Assigned policies set this rule to different modes, so devices may apply neither. Resolve the conflict first.') }
        'NotConfigured' { return (& $Out 'NotConfigured' 'No assigned policy sets this rule. Add it in Audit first.') }
        'Off' { return (& $Out 'NotConfigured' 'The assigned policy turns this rule off. Set it to Audit first.') }
        'Block' {
            if ($Blocked -gt 0) { return (& $Out 'AlreadyBlock' "Already Block. $Blocked block(s) on $Devices device(s) in the last $WindowDays day(s): check they are not your own tools.") }
            return (& $Out 'AlreadyBlock' 'Already Block.')
        }
    }
    if ($Mode -notin @('Audit', 'Warn')) { return (& $Out 'KeepAudit' "Mode '$Mode' is not recognised; not recommending a change.") }

    if ($Evidence.Available -ne $true -or $Reporting -eq 0) {
        $Src = if ($Evidence.Notes) { " ($(@($Evidence.Notes) -join '; '))" } else { '' }
        return (& $Out 'KeepAudit' "No ASR evidence for this tenant$Src, so CIPP cannot show the rule is quiet. Keep Audit.")
    }
    if ($Coverage -lt $WindowDays) {
        return (& $Out 'KeepAudit' "Only $Coverage day(s) of evidence; $WindowDays are needed before recommending Block.")
    }
    $Hits = $Audited + $Warned
    if ($Hits -gt 0) {
        return (& $Out 'KeepAudit' "$Hits audit hit(s) on $Devices device(s) in the last $WindowDays day(s). Review them and add per-rule exclusions before Block.")
    }
    return (& $Out 'ReadyForBlock' "Ready for block: no audit hits in $WindowDays day(s) across $Reporting reporting device(s).")
}
