function Get-CIPPAlertAsrReadiness {
    <#
    .SYNOPSIS
        Monthly ASR audit-to-block readiness summary
    .DESCRIPTION
        Runs Get-CIPPAsrReadiness (14-day window) and raises:
          - each rule in Audit or Warn that is ready for Block (no audit hits over the full window, evidence from
            advanced hunting or the ControlR collector table), as Info;
          - each rule whose assigned policies conflict, as Warning.
        Rules kept in Audit because there is no evidence are not raised one by one: a tenant with Audit rules and
        no evidence source gets one 'NoEvidence' row instead, so the gap is visible without 19 identical rows.
        State mode: Ids are 'Ready|<rule id>', 'Conflict|<rule id>' and 'NoEvidence', so a finding notifies once
        and resolves when the rule changes. Set the alert's re-notify option to repeat it every month.
        A run where the policy inventory had errors reports nothing. Report only: no policy is changed.
        Aspendora fork addition (Vikunja CIPP-26).
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
    try {
        $Report = Get-CIPPAsrReadiness -TenantFilter $TenantFilter -WindowDays 14
        if (@($Report.Errors).Count -gt 0) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "ASR readiness: skipped reporting, could not read everything: $(@($Report.Errors) -join '; ')" -sev Warning
            return
        }
        if ($Report.Summary.AsrPolicies -eq 0) {
            # No ASR policy at all: nothing to promote. Coverage gaps belong to the ControlR digest.
            Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @()
            return
        }
        $Rows = [System.Collections.Generic.List[object]]::new()
        foreach ($R in @($Report.Rules)) {
            if ($R.Recommendation -eq 'ReadyForBlock') {
                $Rows.Add([pscustomobject]@{ Severity = 'Info'; Rule = $R.Rule; Mode = $R.Mode; Recommendation = 'Ready for block'; Message = "ASR rule '$($R.Rule)' is ready for Block: $($R.Reason)"; Policies = $R.Policies; Id = "Ready|$($R.RuleId)" })
            } elseif ($R.Recommendation -eq 'FixConflict') {
                $Rows.Add([pscustomobject]@{ Severity = 'Warning'; Rule = $R.Rule; Mode = $R.Mode; Recommendation = 'Fix conflict'; Message = "ASR rule '$($R.Rule)' is set differently by assigned policies: $($R.Policies)"; Policies = $R.Policies; Id = "Conflict|$($R.RuleId ?? $R.Rule)" })
            }
        }
        $AuditRules = @($Report.Rules | Where-Object { $_.Mode -in @('Audit', 'Warn') }).Count
        if ($AuditRules -gt 0 -and $Report.Evidence.Available -ne $true) {
            $Rows.Add([pscustomobject]@{ Severity = 'Info'; Rule = ''; Mode = 'Audit'; Recommendation = 'Keep audit'; Message = "$AuditRules ASR rule(s) are in Audit but there is no evidence source for this tenant ($(@($Report.Notes) -join '; ')). Feed the ControlR collector into ExecAsrEvidence to get readiness."; Policies = ''; Id = 'NoEvidence' })
        }
        Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data @($Rows)
    } catch {
        $Err = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "ASR readiness check failed: $($Err.NormalizedError)" -sev (Get-CIPPAlertFailureSeverity -ErrorText "$((Get-CippException -Exception $_).NormalizedError) $_") -LogData $Err
    }
}
