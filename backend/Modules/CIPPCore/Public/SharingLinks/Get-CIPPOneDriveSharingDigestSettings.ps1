function Get-CIPPOneDriveSharingDigestSettings {
    <#
    .SYNOPSIS
        The OneDrive sharing digest's sender, preview recipient and, for a tenant, whether it is live.
    .DESCRIPTION
        Stored in the Config table, partition 'OneDriveSharingDigest':
          RowKey 'Settings'      SenderMailbox, SenderTenant, PreviewRecipient (all optional; defaults below)
          RowKey <tenant domain> Live (bool), ApprovedBy, ApprovedUtc
        A tenant with no row, or Live false, is in preview: its digests go to PreviewRecipient.

        Aspendora fork addition.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([string]$TenantFilter)

    $Table = Get-CIPPTable -TableName 'Config'
    $Saved = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'OneDriveSharingDigest' and RowKey eq 'Settings'"
    $Settings = [PSCustomObject]@{
        SenderMailbox    = if ($Saved.SenderMailbox) { [string]$Saved.SenderMailbox } else { 'help@aspendora.com' }
        SenderTenant     = if ($Saved.SenderTenant) { [string]$Saved.SenderTenant } else { 'aspendora.com' }
        PreviewRecipient = if ($Saved.PreviewRecipient) { [string]$Saved.PreviewRecipient } else { 'lacy@aspendora.com' }
        Tenant           = $null
        Live             = $false
        ApprovedBy       = $null
        ApprovedUtc      = $null
    }
    if ($TenantFilter) {
        $Domain = @(Get-Tenants -TenantFilter $TenantFilter -IncludeErrors)[0].defaultDomainName ?? $TenantFilter
        $SafeDomain = ConvertTo-CIPPODataFilterValue -Value $Domain -Type String
        $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'OneDriveSharingDigest' and RowKey eq '$SafeDomain'"
        $Settings.Tenant = $Domain
        $Settings.Live = $Row.Live -eq $true
        $Settings.ApprovedBy = $Row.ApprovedBy
        $Settings.ApprovedUtc = $Row.ApprovedUtc
    }
    return $Settings
}
