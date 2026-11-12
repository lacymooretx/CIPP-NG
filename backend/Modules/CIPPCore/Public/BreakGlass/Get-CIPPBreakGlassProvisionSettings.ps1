function Get-CIPPBreakGlassProvisionSettings {
    <#
    .SYNOPSIS
        Break-glass provisioning settings: Enabled (kill switch for the detector, the approval poll and approved runs)
        and ApprovalSource.
    .DESCRIPTION
        Table BreakGlassProvision, PartitionKey 'Settings', RowKey 'Settings'. A missing row means Enabled and
        ApprovalSource=ControlR.
        ApprovalSource:
          ControlR (default, ONB-13): plans become ControlR change requests that only a Break-Glass Approver can
                    approve, through an interactive sign-in. CIPP's own Action=Approve is refused.
          CIPP:     the original path. ExecBreakGlassProvision Action=Approve (CIPP.SuperAdmin.ReadWrite).
        Set with ExecBreakGlassProvision Action=Settings. Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()
    $Table = Get-CIPPTable -tablename 'BreakGlassProvision'
    $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Settings' and RowKey eq 'Settings'"
    [pscustomobject]@{
        Enabled        = if ($null -eq $Row -or $null -eq $Row.Enabled) { $true } else { [bool]$Row.Enabled }
        ApprovalSource = if ($Row.ApprovalSource -in 'ControlR', 'CIPP') { [string]$Row.ApprovalSource } else { 'ControlR' }
        UpdatedBy      = $Row.UpdatedBy
        UpdatedUtc     = $Row.UpdatedUtc
    }
}
