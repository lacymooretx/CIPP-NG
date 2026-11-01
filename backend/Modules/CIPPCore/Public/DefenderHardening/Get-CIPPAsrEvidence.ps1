function Get-CIPPAsrEvidence {
    <#
    .SYNOPSIS
        ASR hit counts per rule for one tenant, from the best source that works.
    .DESCRIPTION
        1. Defender advanced hunting (POST security/runHuntingQuery, app token): DeviceEvents ActionType 'Asr*'
           over the window. In Defender for Business and single-seat MDE P2 tenants the device tables do not exist
           and Graph answers "Failed to resolve table or column expression" (seen in aspendora.com and 3endt.com,
           2026-07-24); that is reported as a note, not an error. -SkipHunting skips this step.
        2. Table AsrEvidence: one row per device per day, written by ExecAsrEvidence from the ControlR
           Get-AsrEvents collector (Event IDs 1121 block / 1122 audit, which every Windows device logs regardless
           of licence).
        Returns the Measure-CIPPAsrEvidence shape (Available, Source, CoverageDays, DevicesReporting,
        DevicesWithoutRules, ByRule, Notes). Read-only towards the tenant. Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [int]$WindowDays = 14,
        [switch]$SkipHunting
    )
    $Notes = [System.Collections.Generic.List[string]]::new()

    if (-not $SkipHunting) {
        try {
            $Query = "DeviceEvents | where Timestamp > ago($($WindowDays)d) and ActionType startswith 'Asr' | summarize Hits = count(), Devices = dcount(DeviceId) by ActionType"
            $Hunt = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -tenantid $TenantFilter -AsApp $true -body (ConvertTo-Json -InputObject @{ Query = $Query } -Compress)
            $Reporting = 0
            try {
                $Info = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -tenantid $TenantFilter -AsApp $true -body (ConvertTo-Json -InputObject @{ Query = 'DeviceInfo | where Timestamp > ago(1d) | summarize Devices = dcount(DeviceId)' } -Compress)
                $Reporting = [int](@($Info.results)[0].Devices)
            } catch { $Notes.Add("hunting DeviceInfo count failed: $((Get-CippException -Exception $_).NormalizedError)") }

            $Stems = @{}
            foreach ($R in Get-CIPPAsrRuleCatalog) { $Stems[$R.HuntingStem.ToLowerInvariant()] = $R.RuleId }
            $ByRule = @{}
            foreach ($Row in @($Hunt.results)) {
                $Action = [string]$Row.ActionType
                $Kind = if ($Action -match 'Blocked$') { 'Blocked' } elseif ($Action -match 'Warned$') { 'Warned' } else { 'Audited' }
                $Stem = ($Action -replace '(Audited|Blocked|Warned)$', '').ToLowerInvariant()
                $Id = $Stems[$Stem]
                if (-not $Id) { $Notes.Add("hunting ActionType '$Action' is not mapped to a rule"); continue }
                if (-not $ByRule.ContainsKey($Id)) { $ByRule[$Id] = [pscustomobject]@{ Audited = 0; Blocked = 0; Warned = 0; Devices = 0 } }
                $ByRule[$Id].$Kind += [int]$Row.Hits
                # dcount per ActionType: the max is a lower bound on devices with any hit for the rule.
                $ByRule[$Id].Devices = [math]::Max($ByRule[$Id].Devices, [int]$Row.Devices)
            }
            if ($Reporting -gt 0) {
                return [pscustomobject]@{
                    Available           = $true
                    Source              = 'Defender advanced hunting'
                    CoverageDays        = $WindowDays
                    DevicesReporting    = $Reporting
                    DevicesWithoutRules = $null
                    ByRule              = $ByRule
                    Notes               = @($Notes)
                }
            }
            $Notes.Add('advanced hunting ran but no device reported in the last day; falling back to the collector table')
        } catch {
            $Msg = (Get-CippException -Exception $_).NormalizedError
            if ($Msg -match 'Failed to resolve table') {
                $Notes.Add('advanced hunting device tables are not provisioned in this tenant (Defender for Business, or MDE P2 not covering the devices)')
            } else {
                $Notes.Add("advanced hunting unavailable: $Msg")
            }
        }
    }

    $Rows = @()
    try {
        $Table = Get-CIPPTable -tablename 'AsrEvidence'
        $SafeTenant = ConvertTo-CIPPODataFilterValue -Value (Get-CIPPAsrEvidenceTenantKey -TenantFilter $TenantFilter) -Type String
        $Rows = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$SafeTenant'")
    } catch {
        $Notes.Add("AsrEvidence table could not be read: $((Get-CippException -Exception $_).NormalizedError)")
    }
    $Summary = Measure-CIPPAsrEvidence -Rows $Rows -WindowDays $WindowDays
    $Summary.Source = 'ControlR Get-AsrEvents (AsrEvidence table)'
    $Summary.Notes = @($Notes) + @($Summary.Notes)
    $Summary
}
