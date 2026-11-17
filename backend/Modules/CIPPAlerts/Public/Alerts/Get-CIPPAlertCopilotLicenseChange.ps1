function Get-CIPPAlertCopilotLicenseChange {
    <#
    .SYNOPSIS
        Daily alert when a Copilot or Copilot-credit licence appears in a tenant or its seat count changes
    .DESCRIPTION
        Microsoft 365 Copilot Business moves to usage-based billing on 2026-12-01: a new or changed Copilot subscription
        brings an Azure subscription and a default spending policy for all users. The Pax8 watcher only sees licences we
        sell, so this works from the tenant side (subscribedSkus) and also catches direct purchases, other resellers and
        helpdesk changes.

        A SKU counts as Copilot when its skuPartNumber contains COPILOT, AGENT, CCIBOTS (Copilot Studio) or CREDIT, or
        when it carries an M365_COPILOT* service plan (bundles). The purchased seat count (prepaidUnits.enabled) of each
        such SKU is recorded in table KnownCopilotSkus (PartitionKey = tenant, RowKey = skuId; a '_seeded' row marks a
        tenant as initialised). The first run records what exists and raises nothing. After that:
          new SKU, or seats went up     Warning
          seats went down / SKU gone    Info
        Each row is labelled from our CSP subscriptions (Pax8 or Sherweb): 'ours' when the tenant has an active Copilot
        subscription with us, 'bought elsewhere' when it has none (still needs a client conversation), or 'unknown' when
        the tenant is not mapped or the lookup failed. The label never suppresses a row.

        Rows go through the lifecycle in append mode with a stable Id per SKU and seat count, so each change notifies
        once. The new state is recorded after the lifecycle write, so a failure re-raises next run. Report only: nothing
        in the tenant is changed; the table is CIPP's own. Aspendora fork addition (Vikunja CIPP-42).
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
        $Skus = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits,consumedUnits,capabilityStatus,servicePlans' -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.skuId })
        $Copilot = @($Skus | Where-Object {
                ([string]$_.skuPartNumber -match 'COPILOT|AGENT|CCIBOTS|CREDIT') -or
                (@($_.servicePlans.servicePlanName | Where-Object { [string]$_ -like 'M365_COPILOT*' }).Count -gt 0)
            })

        $Table = Get-CIPPTable -tablename 'KnownCopilotSkus'
        $SafeTenant = ConvertTo-CIPPODataFilterValue -Value ([string]$TenantFilter) -Type String
        $Known = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$SafeTenant'")
        $Seeded = @($Known | Where-Object { $_.RowKey -eq '_seeded' }).Count -gt 0
        $KnownSkus = @{}
        foreach ($K in @($Known | Where-Object { $_.RowKey -ne '_seeded' })) { $KnownSkus[([string]$K.RowKey).ToLower()] = $K }

        $NowIso = [datetime]::UtcNow.ToString('o')
        $State = foreach ($S in $Copilot) {
            @{
                PartitionKey  = [string]$TenantFilter
                RowKey        = ([string]$S.skuId).ToLower()
                SkuPartNumber = [string]$S.skuPartNumber
                Enabled       = [int]$S.prepaidUnits.enabled
                Warning       = [int]$S.prepaidUnits.warning
                Suspended     = [int]$S.prepaidUnits.suspended
                Consumed      = [int]$S.consumedUnits
                Status        = [string]$S.capabilityStatus
                Present       = $true
                LastSeenUtc   = $NowIso
            }
        }
        $State = @($State)

        if (-not $Seeded) {
            $Entities = @($State) + @(@{ PartitionKey = [string]$TenantFilter; RowKey = '_seeded'; SeededUtc = $NowIso; SkuCount = $State.Count })
            Add-CIPPAzDataTableEntity @Table -Force -Entity $Entities | Out-Null
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Copilot licences: first run, recorded $($State.Count) Copilot SKU(s) silently$(if ($State.Count) { ': ' + (($State | ForEach-Object { "$($_.SkuPartNumber) $($_.Consumed)/$($_.Enabled)" }) -join ', ') })." -sev Info
            return
        }

        # Work out what changed. Present SKUs first, then known SKUs that are gone.
        $Changes = [System.Collections.Generic.List[object]]::new()
        $CurrentIds = @{}
        foreach ($S in $State) {
            $CurrentIds[$S.RowKey] = $true
            $Old = $KnownSkus[$S.RowKey]
            $OldEnabled = if ($Old -and $Old.Present -ne $false) { [int]$Old.Enabled } else { $null }
            if ($null -eq $OldEnabled) {
                $Changes.Add([pscustomobject]@{ Kind = 'New'; State = $S; OldEnabled = 0 })
            } elseif ($OldEnabled -ne $S.Enabled) {
                $Changes.Add([pscustomobject]@{ Kind = $(if ($S.Enabled -gt $OldEnabled) { 'Up' } else { 'Down' }); State = $S; OldEnabled = $OldEnabled })
            }
        }
        $Gone = foreach ($K in $KnownSkus.Values) {
            if ($CurrentIds.ContainsKey(([string]$K.RowKey).ToLower()) -or $K.Present -eq $false) { continue }
            $G = @{ PartitionKey = [string]$TenantFilter; RowKey = ([string]$K.RowKey).ToLower(); SkuPartNumber = [string]$K.SkuPartNumber; Enabled = 0; Warning = 0; Suspended = 0; Consumed = 0; Status = 'Removed'; Present = $false; LastSeenUtc = $NowIso }
            $Changes.Add([pscustomobject]@{ Kind = 'Gone'; State = $G; OldEnabled = [int]$K.Enabled })
            $G
        }
        $Gone = @($Gone)
        if ($Changes.Count -eq 0) {
            # Consumed seats and timestamps still move; keep the table current without raising anything.
            if ($State.Count -gt 0) { Add-CIPPAzDataTableEntity @Table -Force -Entity $State | Out-Null }
            return
        }

        # Label against our CSP subscriptions once per run.
        $CspSubs = $null
        $CspNote = $null
        try {
            $Provider = Get-CIPPCSPProvider -TenantFilter $TenantFilter
            switch ($Provider) {
                'Pax8' { $CspSubs = @(Get-Pax8Subscriptions -TenantFilter $TenantFilter) }
                'Sherweb' { $CspSubs = @(Get-SherwebCurrentSubscription -TenantFilter $TenantFilter) }
                default { $CspNote = 'tenant is not mapped to Pax8 or Sherweb in CIPP' }
            }
        } catch {
            $CspNote = "CSP lookup failed: $($_.Exception.Message)"
        }

        $Rows = foreach ($C in $Changes) {
            $S = $C.State
            $IsDragon = $S.SkuPartNumber -match 'DRAGON'
            $Source = 'unknown'
            $SourceDetail = $CspNote
            if ($null -ne $CspSubs) {
                $Mine = @($CspSubs | Where-Object {
                        $Name = "$($_.productName) $($_.name) $($_.sku)"
                        $Name -match 'Copilot' -and (($Name -match 'Dragon') -eq $IsDragon)
                    })
                if ($Mine.Count -gt 0) {
                    $Source = 'ours'
                    $SourceDetail = ($Mine | ForEach-Object { "$($_.productName) x$($_.quantity)" }) -join '; '
                } else {
                    $Source = 'bought elsewhere'
                    $SourceDetail = 'no active Copilot subscription with us for this tenant'
                }
            }
            $Seats = "$($S.Consumed) assigned of $($S.Enabled) purchased$(if ($S.Warning) { ", $($S.Warning) in grace" })$(if ($S.Suspended) { ", $($S.Suspended) suspended" })"
            $What = switch ($C.Kind) {
                'New' { "Copilot licence $($S.SkuPartNumber) appeared ($Seats)." }
                'Up' { "Copilot licence $($S.SkuPartNumber) went from $($C.OldEnabled) to $($S.Enabled) purchased seats ($Seats)." }
                'Down' { "Copilot licence $($S.SkuPartNumber) went from $($C.OldEnabled) to $($S.Enabled) purchased seats ($Seats)." }
                'Gone' { "Copilot licence $($S.SkuPartNumber) ($($C.OldEnabled) seats) is no longer in the tenant." }
            }
            $Next = switch ($Source) {
                'ours' { "Bought through us ($SourceDetail). Check it matches the order." }
                'bought elsewhere' { 'Not bought through us: talk to the client about who bought it and the usage-based billing and spending policy that come with Copilot Business from 2026-12-01.' }
                default { "Purchase channel unknown ($SourceDetail)." }
            }
            [pscustomobject]@{
                Id            = "CopilotSku|$($S.RowKey)|$(if ($C.Kind -eq 'Gone') { 'removed' } else { $S.Enabled })"
                Severity      = $(if ($C.Kind -in @('New', 'Up')) { 'Warning' } else { 'Info' })
                Change        = $C.Kind
                SkuPartNumber = $S.SkuPartNumber
                SkuId         = $S.RowKey
                PreviousSeats = $C.OldEnabled
                Seats         = $S.Enabled
                Assigned      = $S.Consumed
                Source        = $Source
                SourceDetail  = $SourceDetail
                Message       = "$What $Next"
            }
        }
        $Rows = @($Rows)
        $Notify = @(Write-AlertTrace -cmdletName ([string]$MyInvocation.MyCommand) -tenantFilter $TenantFilter -data $Rows -Append | Where-Object { $_ })
        # Recorded after the lifecycle write, so a failure above re-raises next run (the lifecycle de-duplicates).
        $Entities = @($State) + @($Gone)
        if ($Entities.Count -gt 0) { Add-CIPPAzDataTableEntity @Table -Force -Entity $Entities | Out-Null }
        $Notify
    } catch {
        $ErrorData = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Copilot licence check failed: $($ErrorData.NormalizedError)" -sev (Get-CIPPAlertFailureSeverity -ErrorText "$($ErrorData.NormalizedError) $_") -LogData $ErrorData
    }
}
