function Invoke-CIPPAdminInventorySync {
    <#
    .SYNOPSIS
        Writes or updates the Hudu article "Microsoft 365 admins — <client>" for one tenant or every tenant.
    .DESCRIPTION
        Read-only towards Microsoft 365, so it covers managed and unmanaged tenants alike (Lacy, 2026-11-12).
        One article per Hudu company, matched by exact name and updated in place, then read back. A tenant with
        no Hudu mapping is skipped and reported. Failures go to Lacy as one email (no ticket) per run.
        -Preview returns the inventory and HTML without writing to Hudu.
        Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [string]$TenantFilter,
        [switch]$Preview,
        [switch]$NoAlert
    )
    $APIName = 'AdminInventory'
    $Results = [System.Collections.Generic.List[object]]::new()
    $Configuration = $null
    if (-not $Preview) {
        $Table = Get-CIPPTable -TableName Extensionsconfig
        $Configuration = (Get-CIPPAzDataTableEntity @Table).config | ConvertFrom-Json -ErrorAction Stop
        if ($Configuration.Hudu.Enabled -ne $true) { throw 'The Hudu integration is not enabled.' }
    }
    $Tenants = if ($TenantFilter) { @(Get-Tenants -TenantFilter $TenantFilter) } else { @(Get-Tenants) }

    foreach ($T in $Tenants) {
        $R = [ordered]@{ Tenant = $T.defaultDomainName; Status = 'Failed'; ArticleId = $null; Admins = $null; Flagged = $null; Message = $null; Html = $null }
        try {
            $Company = Get-HuduCompanyId -TenantFilter $T.defaultDomainName
            if (-not $Company -and -not $Preview) { $R.Status = 'Skipped'; $R.Message = 'No Hudu company mapping (Extensions > Hudu > Mappings).'; $Results.Add([pscustomobject]$R); continue }
            $Inv = Get-CIPPAdminInventory -TenantFilter $T.defaultDomainName
            $Name = "Microsoft 365 admins — $($Company.CompanyName ?? $T.displayName)"
            $Html = ConvertTo-CIPPAdminInventoryHtml -Inventory $Inv -ClientName ($Company.CompanyName ?? $T.displayName)
            $R.Admins = @($Inv.Admins).Count
            $R.Flagged = @($Inv.Admins | Where-Object { @($_.Flags).Count -gt 0 }).Count
            if ($Preview) { $R.Status = 'Preview'; $R.Html = $Html; $R.Inventory = $Inv; $Results.Add([pscustomobject]$R); continue }

            # Hudu ignores unknown query parameters, so match the name client-side.
            $Listed = @((Invoke-CippHuduRequest -Configuration $Configuration -Resource '/articles' -Params @{ company_id = $Company.CompanyId; name = $Name; page_size = 100 }).articles |
                    Where-Object { $_.name -eq $Name -and [string]$_.company_id -eq [string]$Company.CompanyId -and -not $_.archived })
            if ($Listed.Count -gt 1) { throw "$($Listed.Count) articles named '$Name' in this company. Archive the extras by hand." }
            $Body = @{ article = @{ name = $Name; content = $Html; company_id = [int]$Company.CompanyId } }
            $Saved = if ($Listed.Count -eq 1) {
                (Invoke-CippHuduRequest -Configuration $Configuration -Method PUT -Resource "/articles/$($Listed[0].id)" -Body $Body).article
            } else {
                (Invoke-CippHuduRequest -Configuration $Configuration -Method POST -Resource '/articles' -Body $Body).article
            }
            $Back = (Invoke-CippHuduRequest -Configuration $Configuration -Resource "/articles/$($Saved.id)").article
            if ($Back.name -ne $Name -or [string]$Back.company_id -ne [string]$Company.CompanyId -or $Back.content -notmatch 'Generated automatically by CIPP') { throw "Read-back of Hudu article $($Saved.id) did not match what was written." }
            $R.Status = $(if ($Listed.Count -eq 1) { 'Updated' } else { 'Created' }); $R.ArticleId = $Back.id; $R.Message = $Back.url
        } catch {
            $R.Message = Get-NormalizedError -Message $_.Exception.Message
        }
        $Results.Add([pscustomobject]$R)
    }

    $Failed = @($Results | Where-Object Status -EQ 'Failed')
    if ($Failed.Count -and -not $Preview -and -not $NoAlert) {
        $Title = "Admin inventory to Hudu: $($Failed.Count) tenant(s) failed"
        $Html = "<p>The weekly Microsoft 365 admin inventory could not update these tenants' Hudu articles.</p>$($Failed | Select-Object Tenant, Message | ConvertTo-Html -Fragment | Out-String)"
        try { $null = Send-CIPPAlert -Type 'email' -Title $Title -HTMLContent $Html -TenantFilter $env:TenantID -APIName $APIName } catch { Write-Information "Admin inventory alert failed: $($_.Exception.Message)" }
    }
    Write-LogMessage -API $APIName -tenant 'Global' -message "Admin inventory: $(@($Results | Where-Object Status -In 'Created','Updated').Count) written, $(@($Results | Where-Object Status -EQ 'Skipped').Count) skipped, $($Failed.Count) failed" -Sev 'Info'
    return @($Results)
}
