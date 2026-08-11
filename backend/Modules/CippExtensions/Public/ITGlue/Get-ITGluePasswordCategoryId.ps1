function Get-ITGluePasswordCategoryId {
    <#
    .SYNOPSIS
    Resolves an IT Glue password category name to its id.

    .DESCRIPTION
    Cached for the life of the process: categories are a small, near-static taxonomy and
    this is called on every password write. Returns $null when the category does not
    exist, in which case the caller should write the record without a category rather
    than fail.

    Requires Connect-ITGlueAPI to have been called.

    Aspendora fork addition.

    .PARAMETER Name
    The category name, e.g. 'Office 365'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $script:ITGluePasswordCategoryCache) {
        $script:ITGluePasswordCategoryCache = @{}
    }
    if ($script:ITGluePasswordCategoryCache.ContainsKey($Name)) {
        return $script:ITGluePasswordCategoryCache[$Name]
    }

    try {
        $Encoded = [System.Uri]::EscapeDataString($Name)
        $Categories = Invoke-ITGlueRequest -Path "/password_categories?filter[name]=$Encoded" -AllPages
        $Match = $Categories | Where-Object { $_.attributes.name -eq $Name } | Select-Object -First 1
        $CategoryId = if ($Match) { $Match.id } else { $null }
        $script:ITGluePasswordCategoryCache[$Name] = $CategoryId
        return $CategoryId
    } catch {
        Write-LogMessage -API 'ITGlue' -message "Could not resolve the IT Glue password category '$Name': $($_.Exception.Message)" -Sev 'Warning'
        return $null
    }
}
