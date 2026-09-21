function Test-CIPPCloudPCLicensed {
    <#
    .FUNCTIONALITY
    Internal
    .DESCRIPTION
        Does this tenant own any Windows 365 / Cloud PC licence?

        Used to tell "no Windows 365 here" apart from "no access", which the Cloud PC API itself
        refuses to distinguish - see Get-CIPPCloudPCCollection.

        Matching is on skuPartNumber and is deliberately loose. Microsoft's catalogue part numbers
        are CPC_* (CPC_E_16C_64GB_512GB and friends), but a live tenant can also report the
        descriptive form: aspendora.com returns 'Windows_365_Enterprise_16_vCPU,_64_GB,_512_GB'.
        Both shapes were read off real tenants; matching only CPC_ would have missed the one
        tenant we actually have.

        Returns $null - not $false - when the SKU list itself cannot be read, so a caller never
        reports "unlicensed" on the strength of a failed lookup.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter
    )

    try {
        $Skus = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits' -tenantid $TenantFilter -AsApp $true -ErrorAction Stop
    } catch {
        Write-Information "Test-CIPPCloudPCLicensed: could not read subscribedSkus for $TenantFilter - licence state unknown."
        return $null
    }

    foreach ($Sku in @($Skus)) {
        if ("$($Sku.skuPartNumber)" -match '(?i)^CPC_|windows[_ ]?365') {
            # A SKU that exists but has no enabled units buys nothing.
            if ($null -eq $Sku.prepaidUnits -or [int]$Sku.prepaidUnits.enabled -gt 0) { return $true }
        }
    }
    return $false
}
