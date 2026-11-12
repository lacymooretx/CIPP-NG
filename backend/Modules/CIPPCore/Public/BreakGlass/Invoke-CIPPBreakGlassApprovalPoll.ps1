function Invoke-CIPPBreakGlassApprovalPoll {
    <#
    .SYNOPSIS
        Pulls approved break-glass change requests from ControlR, checks each against CIPP's own stored plan, claims
        it, runs it, and writes the result back. ControlR never holds a credential that can make CIPP create accounts.
    .DESCRIPTION
        For each approved, unexpired, unclaimed request, the checks below must all pass, or CIPP posts Refused with
        the reason and creates nothing:
          - a stored plan row exists for planId (= tenant id) and is Pending;
          - the row's ChangeRequestId and PlanHash equal the request's, AND the hash recomputed from the stored plan
            matches (CIPP runs its own plan, never content from ControlR);
          - entraTenantId equals the plan's tenant;
          - approverHeldRole is true, and approvedBy is not the CIPP integration service user.
        It then claims the request (POST result Running; a 409 means another worker has it, so skip) and runs
        Invoke-CIPPBreakGlassProvision. That function re-plans and refuses on drift, keeps the kill switch, and
        snapshots and reads back every change. Result: Succeeded (all steps OK), Refused (nothing was created) or
        Failed (partial; see the run). The detail sent back holds no secrets and stays under 8 KB.
        Only when Settings.ApprovalSource = ControlR. Aspendora fork addition (ONB-13).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()
    $APIName = 'BreakGlassProvision'
    $Settings = Get-CIPPBreakGlassProvisionSettings
    if (-not $Settings.Enabled -or $Settings.ApprovalSource -ne 'ControlR') { return @() }
    $Table = Get-CIPPTable -tablename 'BreakGlassProvision'
    $List = Invoke-CippControlRIntegrationRequest -Method GET -Path 'change-requests/break-glass?status=Approved'
    if ($List.Status -ne 200) {
        Write-LogMessage -API $APIName -tenant 'Global' -message "Break-glass approval poll could not list ControlR approvals: $($List.Message)" -Sev 'Warning'
        return @()
    }
    $Out = [System.Collections.Generic.List[object]]::new()
    $Post = {
        param($Id, $Status, $RunId, $Summary, $Detail)
        if ($Detail -and $Detail.Length -gt 7900) { $Detail = $Detail.Substring(0, 7900) + '…' }
        Invoke-CippControlRIntegrationRequest -Method POST -Path "change-requests/break-glass/$Id/result" -Body @{ status = $Status; runId = $RunId; summary = $Summary; detail = $Detail }
    }

    foreach ($CR in @($List.Data)) {
        $CrId = [string]$CR.changeRequestId
        $RunId = (New-Guid).Guid
        $PlanId = ([string]$CR.planId).ToLower()
        $Row = if ($PlanId -match '^[0-9a-f-]{36}$') { Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Plan' and RowKey eq '$PlanId'" }
        $Plan = if ($Row.PlanJson) { $Row.PlanJson | ConvertFrom-Json }
        $Why = if (-not $Row -or -not $Plan) { "CIPP has no stored plan for planId $PlanId." }
        elseif ($Row.Status -ne 'Pending') { "CIPP's plan for this tenant is '$($Row.Status)', not Pending." }
        elseif ([string]$Row.ChangeRequestId -ne $CrId) { "This is not the change request CIPP posted for the current plan ($($Row.ChangeRequestId))." }
        elseif ([string]$Row.PlanHash -ne [string]$CR.planHash -or (Get-CIPPBreakGlassPlanHash -Plan $Plan) -ne [string]$CR.planHash) { 'The plan hash does not match CIPP''s stored plan.' }
        elseif (([string]$CR.entraTenantId).ToLower() -ne ([string]$Plan.TenantId).ToLower()) { 'The tenant does not match CIPP''s stored plan.' }
        elseif ($CR.approverHeldRole -ne $true) { 'The approver did not hold the Break-Glass Approver role.' }
        elseif ([string]$CR.approvedBy.upn -match '^svc-cipp-integration@') { 'The CIPP integration account cannot approve its own request.' }
        else { $null }

        if ($Why) {
            $null = & $Post $CrId 'Refused' $RunId 'Refused by CIPP before any change.' $Why
            Write-LogMessage -API $APIName -tenant ($Plan.Tenant ?? 'Global') -message "Refused ControlR change request $($CrId): $Why" -Sev 'Warning'
            $Out.Add([pscustomobject]@{ ChangeRequestId = $CrId; Tenant = $Plan.Tenant; Result = 'Refused'; Reason = $Why })
            continue
        }

        $Claim = & $Post $CrId 'Running' $RunId "CIPP run started for $($Plan.Tenant)." $null
        if ($Claim.Status -ne 200) { $Out.Add([pscustomobject]@{ ChangeRequestId = $CrId; Tenant = $Plan.Tenant; Result = 'NotClaimed'; Reason = $Claim.Message }); continue }

        $Approver = "$($CR.approvedBy.upn) via ControlR change request $CrId"
        $Row.Status = 'Running'
        $Row | Add-Member -NotePropertyName ApprovedBy -NotePropertyValue $Approver -Force
        $Row | Add-Member -NotePropertyName ApprovedUtc -NotePropertyValue ([string]$CR.approvedAt) -Force
        Add-CIPPAzDataTableEntity @Table -Entity $Row -Force
        Write-LogMessage -API $APIName -tenant $Plan.Tenant -message "Break-glass plan approved by $Approver; run starting." -Sev 'Warning'

        try {
            $Run = Invoke-CIPPBreakGlassProvision -TenantFilter $Plan.Tenant -ApprovedPlan $Plan -ApprovedBy $Approver -RunId $RunId
        } catch {
            $Run = [pscustomobject]@{ RunId = $RunId; Status = 'Failed'; Accounts = @(); Steps = @([pscustomobject]@{ Step = 'Run'; Ok = $false; Detail = (Get-NormalizedError -Message $_.Exception.Message) }) }
        }
        $Created = @($Run.Accounts).Count
        $Final = if ($Run.Status -eq 'Succeeded') { 'Succeeded' } elseif ($Created -eq 0) { 'Refused' } else { 'Failed' }
        if ($Created -eq 0) {
            $Back = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Plan' and RowKey eq '$PlanId'"
            if ($Back.Status -eq 'Running') { $Back.Status = 'Failed'; Add-CIPPAzDataTableEntity @Table -Entity $Back -Force }
        }
        $Detail = "CIPP run $($Run.RunId). Accounts: $((@($Run.Accounts) | ForEach-Object UserPrincipalName) -join ', '). " +
        (($Run.Steps | ForEach-Object { "[$(if ($_.Ok) { 'ok' } else { 'FAIL' })] $($_.Step): $($_.Detail)" }) -join ' | ')
        $Res = & $Post $CrId $Final $RunId "CIPP run $($Run.RunId): $($Run.Status)." $Detail
        if ($Res.Status -ne 200) { Write-LogMessage -API $APIName -tenant $Plan.Tenant -message "Could not write the result back to ControlR change request $($CrId): $($Res.Message)" -Sev 'Warning' }
        $Out.Add([pscustomobject]@{ ChangeRequestId = $CrId; Tenant = $Plan.Tenant; Result = $Final; RunId = $Run.RunId })
    }
    return @($Out)
}
