function Get-CIPPAlertStorageQuota {
    <#
    .FUNCTIONALITY
        Entrypoint
    .SYNOPSIS
        Alert on mailboxes genuinely near their quota, for managed clients only.
    .DESCRIPTION
        Differs from the built-in Get-CIPPAlertQuotaUsed in three ways that exist because
        of what real tenant data and real ticket history did to the naive version:

        1. MANAGED CLIENTS ONLY. Membership syncs daily from ConnectWise, so scope follows
           the agreement rather than a list somebody has to remember to update. An
           unmanaged client generates no alert and no ticket.

        2. BANDED NOTIFICATION. Findings are notified once and then held until they cross a
           band (85 -> 90 -> 95) or the re-notify window elapses (Select-CIPPStorageAlertToNotify).
           The AlertLifecycle added in CIPP 11.0 cannot express bands or reminders, so it does
           not decide notifications here. It is still reconciled silently every run with the
           full at-risk set (keyed on UserPrincipalName), so the alert-management page shows
           the true state, and a snooze set there suppresses this alert's notifications too.

        3. JUDGED ON THE HARD QUOTA. issueWarningQuota is not always rescaled when a
           mailbox moves to a larger plan - on 3E NDT it sits at 45 GB on a 100 GB mailbox -
           so alerting on it raises capacity tickets for mailboxes with 30 GB free.

    .PARAMETER InputValue
        Optional settings: StorageQuotaPercent (default 85), StorageReNotifyDays (14).
    .PARAMETER TenantFilter
        Tenant to check.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        [Parameter(Mandatory)]
        $TenantFilter
    )

    $Threshold = if ($InputValue.StorageQuotaPercent) { [int]$InputValue.StorageQuotaPercent } else { 85 }
    $ReNotifyDays = if ($InputValue.StorageReNotifyDays) { [int]$InputValue.StorageReNotifyDays } else { 14 }

    # ---- managed gate ----------------------------------------------------------------
    $CmdletName = [string]$MyInvocation.MyCommand
    $Managed = Test-CIPPTenantManaged -TenantFilter $TenantFilter
    if (-not $Managed.IsManaged) {
        # Silent. A log line per unmanaged tenant per run is its own kind of noise, and the
        # scope decision is already visible in the tenant group. Out of scope is a real
        # "clear", so anything left open from when it was managed resolves.
        $null = Write-AlertTrace -cmdletName $CmdletName -tenantFilter $TenantFilter -data @()
        return
    }

    try {
        $Mailboxes = New-GraphGetRequest -tenantid $TenantFilter -AsApp $true `
            -uri "https://graph.microsoft.com/beta/reports/getMailboxUsageDetail(period='D7')?`$format=application/json&`$top=999"
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -sev Error -LogData $ErrorMessage `
            -message "Storage quota alert: could not read mailbox usage: $($ErrorMessage.NormalizedError)"
        return
    }

    $Risk = Get-CIPPMailboxQuotaRisk -Mailboxes $Mailboxes -RiskPercent $Threshold

    # Bands, not percentages: a mailbox drifting 91% -> 92% must not re-alert.
    $Findings = foreach ($M in $Risk.AtRisk) {
        $Band = if ($M.PercentUsed -ge 95) { 95 } elseif ($M.PercentUsed -ge 90) { 90 } else { $Threshold }
        @{
            Key     = "Mailbox:$($M.Upn)"
            Band    = $Band
            Message = "$($M.Upn) is $($M.PercentUsed)% full ($([math]::Round($M.UsedBytes / 1GB, 2)) GB of $([math]::Round($M.HardBytes / 1GB, 2)) GB). Remaining: $([math]::Round(($M.HardBytes - $M.UsedBytes) / 1GB, 2)) GB."
        }
    }
    $Findings = @($Findings)

    # ---- suppression state --------------------------------------------------------------
    $Table = Get-CIPPTable -TableName 'CippStorageAlertState'
    $RowKey = 'MailboxQuota'
    $Prior = @{}
    $Entity = $null
    try {
        $Entity = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey eq '$RowKey'" | Select-Object -First 1
        if ($Entity -and $Entity.State) {
            $Parsed = $Entity.State | ConvertFrom-Json -ErrorAction Stop
            foreach ($Property in $Parsed.PSObject.Properties) {
                $Prior[$Property.Name] = @{ Band = $Property.Value.Band; LastNotified = $Property.Value.LastNotified }
            }
        }
    } catch {
        # Unreadable state means we cannot prove anything was already sent. Fall through
        # with an empty prior: better a duplicate ticket than a silently swallowed 95%.
        $Prior = @{}
    }

    $Decision = Select-CIPPStorageAlertToNotify -Findings $Findings -Prior $Prior `
        -Now (Get-Date).ToUniversalTime() -ReNotifyDays $ReNotifyDays

    try {
        $null = Add-CIPPAzDataTableEntity @Table -Force -Entity @{
            PartitionKey = [string]$TenantFilter
            RowKey       = $RowKey
            State        = [string]($Decision.State | ConvertTo-Json -Depth 5 -Compress)
            UpdatedAt    = [string](Get-Date).ToUniversalTime().ToString('o')
        }
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -sev Warning `
            -message "Storage quota alert: could not persist suppression state; findings may repeat. $($_.Exception.Message)"
    }

    # Honest lifecycle state, reconciled silently: notifications are decided by the bands above.
    $CurrentItems = @(foreach ($M in @($Risk.AtRisk)) {
            [PSCustomObject]@{
                UserPrincipalName = $M.Upn
                PercentUsed       = $M.PercentUsed
                Message           = "$($M.Upn) is $($M.PercentUsed)% full."
            }
        })
    $null = Write-AlertTrace -cmdletName $CmdletName -tenantFilter $TenantFilter -data $CurrentItems

    if (@($Decision.Notify).Count -eq 0) { return }

    $Snoozes = @{}
    try { $Snoozes = Get-CIPPActiveAlertSnoozes -CmdletName $CmdletName -TenantFilter $TenantFilter } catch {}

    foreach ($N in $Decision.Notify) {
        $M = @($Risk.AtRisk) | Where-Object { "Mailbox:$($_.Upn)" -eq $N.Key } | Select-Object -First 1
        $Item = [PSCustomObject]@{
            Message            = $N.Message
            UserPrincipalName  = $M.Upn
            PercentUsed        = $M.PercentUsed
            StorageUsedInBytes = $M.UsedBytes
            QuotaInBytes       = $M.HardBytes
            RemainingBytes     = ($M.HardBytes - $M.UsedBytes)
            HasArchive         = $M.HasArchive
            RecipientType      = $M.RecipientType
            Notified           = $N.Reason
        }
        if ($Snoozes -and $Snoozes.ContainsKey((Get-AlertContentHash -AlertItem $Item).ContentHash)) { continue }
        $Item
    }
}
