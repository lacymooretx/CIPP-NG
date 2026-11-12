function Invoke-CIPPBreakGlassKeeperHandoff {
    <#
    .SYNOPSIS
        Hands CIPP-provisioned break-glass accounts that are still "Keeper pending" to ControlR, which sets the real
        password and writes Keeper (and Hudu). Safe to call repeatedly.
    .DESCRIPTION
        Picks registry rows that CIPP provisioned (ProvisionRunId set) with no KeeperRecordUid. ControlR checks Global
        Admin through CIPP right after it is assigned, and Entra role reads can lag a fresh assignment by about a
        minute, so a 409 "not an active Global Administrator" is treated as retryable: the account stays pending and
        the next call (Action=Handoff, or the daily timer) tries again. ControlR writes nothing before that check
        passes. Every other refusal (not managed, rotation or Keeper off, UPN mismatch) needs a person, so it alerts
        once per account and reason.
        Contract: ControlR f46de0ba8, POST /api/integration/break-glass/rotate (Hudu 841).
        Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [string]$TenantFilter,
        # Returned rows only; no alert. The caller (the provisioning run) reports the result itself.
        [switch]$NoAlert
    )
    $APIName = 'BreakGlassProvision'
    $Registry = Get-CIPPTable -tablename 'BreakGlassAccounts'
    $Rows = @(if ($TenantFilter) { Get-CIPPBreakGlassAccounts -TenantFilter $TenantFilter } else { Get-CIPPBreakGlassAccounts }) |
        Where-Object { $_.ProvisionRunId -and -not $_.KeeperRecordUid }
    $Out = [System.Collections.Generic.List[object]]::new()

    foreach ($Row in $Rows) {
        $Hand = Invoke-CippControlRIntegrationRequest -Method POST -Path 'break-glass/rotate' -TimeoutSec 90 -Body @{ entraTenantId = $Row.PartitionKey; entraObjectId = $Row.RowKey; upn = $Row.UserPrincipalName }
        $Ok = $Hand.Status -eq 200 -and $Hand.Data.status -eq 'Success' -and $Hand.Data.keeperRecordUid
        $Lag = $Hand.Status -eq 409 -and [string]$Hand.Message -match 'not an active Global Administrator'
        $State = if ($Ok) { 'Rotated' } elseif ($Lag) { 'Retrying (Global Admin not visible yet)' } elseif ($Hand.Status -in 0, 502, 504) { 'Retrying (ControlR unavailable or rotation incomplete)' } else { 'NeedsAttention' }
        $Item = [pscustomobject]@{ Tenant = $Row.PartitionKey; UserPrincipalName = $Row.UserPrincipalName; Status = $State; KeeperRecordUid = $(if ($Ok) { [string]$Hand.Data.keeperRecordUid }); HuduPasswordId = $Hand.Data.huduPasswordId; RotatedAt = $Hand.Data.rotatedAt; Message = $Hand.Message }
        $Out.Add($Item)

        if ($Ok) {
            $Row | Add-Member -NotePropertyName KeeperRecordUid -NotePropertyValue ([string]$Hand.Data.keeperRecordUid) -Force
            $Row | Add-Member -NotePropertyName HuduPasswordId -NotePropertyValue ([string]$Hand.Data.huduPasswordId) -Force
            $Row | Add-Member -NotePropertyName KeeperRotatedUtc -NotePropertyValue ([string]$Hand.Data.rotatedAt) -Force
            $Row | Add-Member -NotePropertyName HandoffProblem -NotePropertyValue '' -Force
            Add-CIPPAzDataTableEntity @Registry -Entity $Row -Force
            Write-LogMessage -API $APIName -tenant $Row.PartitionKey -message "Break-glass $($Row.UserPrincipalName) rotated by ControlR into Keeper record $($Hand.Data.keeperRecordUid)" -Sev 'Info'
            continue
        }
        if ($State -ne 'NeedsAttention') { continue }
        # Alert once per account and reason, not every day.
        if ($Row.HandoffProblem -eq $Hand.Message) { continue }
        $Row | Add-Member -NotePropertyName HandoffProblem -NotePropertyValue ([string]$Hand.Message) -Force
        Add-CIPPAzDataTableEntity @Registry -Entity $Row -Force
        if (-not $NoAlert) {
            $Tenant = (Get-Tenants -TenantFilter $Row.PartitionKey | Select-Object -First 1).defaultDomainName
            $Title = "Break-glass Keeper hand-off refused for $($Row.UserPrincipalName)"
            $Html = "<p>ControlR refused to take over the password of break-glass account $([System.Net.WebUtility]::HtmlEncode($Row.UserPrincipalName)). The account keeps a random password nobody knows (safe, but unusable) until this is fixed.</p><p>$([System.Net.WebUtility]::HtmlEncode($Hand.Message))</p><p>After fixing it, retry with POST /api/ExecBreakGlassProvision {`"tenantFilter`":`"$Tenant`",`"Action`":`"Handoff`"}.</p>"
            foreach ($Channel in 'email', 'psa') {
                try { $null = Send-CIPPAlert -Type $Channel -Title $Title -HTMLContent $Html -TenantFilter ($Tenant ?? $Row.PartitionKey) -APIName $APIName }
                catch { Write-LogMessage -API $APIName -tenant $Row.PartitionKey -message "Could not send $Channel alert for '$Title': $($_.Exception.Message)" -Sev 'Warning' }
            }
        }
    }
    return @($Out)
}
