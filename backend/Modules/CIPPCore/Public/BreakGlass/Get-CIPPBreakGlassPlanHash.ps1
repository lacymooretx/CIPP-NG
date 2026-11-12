function Get-CIPPBreakGlassPlanHash {
    <#
    .SYNOPSIS
        SHA-256 (hex) of exactly what a break-glass plan would do. A ControlR change request is tied to this hash.
    .DESCRIPTION
        Covers the tenant, the exact account UPNs, the group action and id, and the sorted CA policy ids. CIPP only
        runs an approval whose hash equals the hash of its own stored plan, so ControlR can never supply or alter
        what gets executed. Pure function. Aspendora fork addition (ONB-13).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)]$Plan)
    $Canonical = @(
        "tenant=$(([string]$Plan.TenantId).ToLowerInvariant())"
        "accounts=$((@($Plan.AccountsToCreate) | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object) -join ',')"
        "group=$($Plan.GroupAction)|$(([string]$Plan.GroupId).ToLowerInvariant())"
        "policies=$((@($Plan.PolicyEdits) | ForEach-Object { ([string]$_.Id).ToLowerInvariant() } | Sort-Object) -join ',')"
    ) -join "`n"
    $Bytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Canonical))
    return ([System.Convert]::ToHexString($Bytes)).ToLowerInvariant()
}
