function Send-CIPPVendorAccessReport {
    <#
    .SYNOPSIS
        Refreshes the Vendor Access snapshot for all tenants and emails the weekly summary.
    .DESCRIPTION
        Recipient: -Recipient, else the Settings/Weekly row of the CippVendorAccess table, else lacy@aspendora.com.
        Sends through Send-CIPPAlert (CIPP's notification mail path, from the CIPP tenant). -SkipRefresh mails the
        saved snapshot without rebuilding it. Returns @{ Recipient; Subject; Summary; Sent }.
        Aspendora fork addition (Vendor Access).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [string]$Recipient,
        [switch]$SkipRefresh,
        [string]$SubjectPrefix = ''
    )

    $Table = Get-CIPPTable -TableName 'CippVendorAccess'
    if (-not $Recipient) {
        $Settings = try { Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Settings' and RowKey eq 'Weekly'" } catch { $null }
        $Recipient = if ($Settings.Recipient -like '*@*') { [string]$Settings.Recipient } else { 'lacy@aspendora.com' }
    }
    $Snapshot = if ($SkipRefresh) { Get-CIPPVendorAccessSnapshot -TenantFilter 'AllTenants' } else { Update-CIPPVendorAccessSnapshot -TenantFilter 'AllTenants' }
    $S = $Snapshot.Summary
    $Parts = @("$($S.ThirdPartyItems) outside parties")
    if ($S.New) { $Parts += "$($S.New) new" }
    if ($S.HighRisk) { $Parts += "$($S.HighRisk) high risk" }
    if ($S.Stale) { $Parts += "$($S.Stale) stale" }
    $Subject = "$($SubjectPrefix)Vendor access: $($Parts -join ', ') across $($S.Tenants) tenants"
    $Html = New-CIPPVendorAccessHtml -Snapshot $Snapshot
    Send-CIPPAlert -Type 'email' -Title $Subject -HTMLContent $Html -altEmail $Recipient -TenantFilter 'AllTenants' -APIName 'VendorAccess' | Out-Null
    Write-LogMessage -API 'VendorAccess' -tenant 'Global' -message "Vendor access report sent to $Recipient ($($S.ThirdPartyItems) items, $($S.New) new)" -Sev 'Info'
    [pscustomobject]@{ Recipient = $Recipient; Subject = $Subject; Summary = $S; Sent = $true }
}
