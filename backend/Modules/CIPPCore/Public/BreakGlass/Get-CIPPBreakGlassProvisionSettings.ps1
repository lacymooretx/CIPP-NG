function Get-CIPPBreakGlassProvisionSettings {
    <#
    .SYNOPSIS
        Break-glass provisioning settings. Enabled is the kill switch for both the daily detector and approved runs.
    .DESCRIPTION
        Table BreakGlassProvision, PartitionKey 'Settings', RowKey 'Settings'. Missing row means Enabled.
        Set with ExecBreakGlassProvision Action=Settings Enabled=false. Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()
    $Table = Get-CIPPTable -tablename 'BreakGlassProvision'
    $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Settings' and RowKey eq 'Settings'"
    [pscustomobject]@{
        Enabled   = if ($null -eq $Row -or $null -eq $Row.Enabled) { $true } else { [bool]$Row.Enabled }
        UpdatedBy = $Row.UpdatedBy
        UpdatedUtc = $Row.UpdatedUtc
    }
}
