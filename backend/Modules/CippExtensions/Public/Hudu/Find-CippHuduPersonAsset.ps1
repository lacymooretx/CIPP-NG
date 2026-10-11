function Find-CippHuduPersonAsset {
    <#
    .SYNOPSIS
    Finds the single Hudu People asset for a UPN in a company.

    .DESCRIPTION
    Looks in the asset layout mapped to 'Users' on the Hudu extension (Settings ->
    Integrations -> Hudu -> Field Mapping), falling back to the layout named 'People'.
    Matches the same way the Hudu extension sync does: the 'Email Address' field or
    the asset's primary_mail, case-insensitively.

    Returns the asset when exactly one live asset matches, otherwise $null. Two matches
    means a duplicate person, and guessing would attach a credential to the wrong one.

    Never throws: attaching a password to a person is a convenience, and a lookup
    failure must not stop the password being documented.

    Aspendora fork addition (IT Glue -> Hudu migration, 2026-10).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Configuration,

        [Parameter(Mandatory)]
        [string]$CompanyId,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    try {
        $LayoutId = $null
        try {
            $MappingTable = Get-CIPPTable -TableName 'CippMapping'
            $LayoutId = (Get-CIPPAzDataTableEntity @MappingTable -Filter "PartitionKey eq 'HuduFieldMapping' and RowKey eq 'Users'" | Select-Object -First 1).IntegrationId
        } catch { $LayoutId = $null }

        if ([string]::IsNullOrWhiteSpace($LayoutId)) {
            $Layouts = Invoke-CippHuduRequest -Configuration $Configuration -Resource '/asset_layouts' -Params @{ name = 'People' }
            $LayoutId = (@($Layouts.asset_layouts) | Where-Object { $_.name -eq 'People' } | Select-Object -First 1).id
        }
        if ([string]::IsNullOrWhiteSpace($LayoutId)) { return $null }

        $Assets = [System.Collections.Generic.List[object]]::new()
        $Page = 1
        do {
            $Response = Invoke-CippHuduRequest -Configuration $Configuration -Resource '/assets' -Params @{ company_id = $CompanyId; asset_layout_id = $LayoutId; page = $Page; page_size = 1000 }
            $Batch = @($Response.assets)
            foreach ($Asset in $Batch) { $Assets.Add($Asset) }
            $Page++
        } while ($Batch.Count -eq 1000 -and $Page -le 20)

        $Matched = @($Assets | Where-Object {
                # Re-check company and layout: Hudu ignores filters it does not recognise.
                "$($_.company_id)" -eq "$CompanyId" -and "$($_.asset_layout_id)" -eq "$LayoutId" -and $_.archived -ne $true -and (
                    $_.primary_mail -eq $UserPrincipalName -or
                    @($_.fields | Where-Object { $_.label -eq 'Email Address' -and $_.value -eq $UserPrincipalName }).Count -gt 0
                )
            })

        if ($Matched.Count -eq 1) { return $Matched[0] }
        return $null
    } catch {
        Write-Information "Hudu person lookup for $UserPrincipalName failed: $($_.Exception.Message)"
        return $null
    }
}
