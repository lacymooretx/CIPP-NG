function Get-CIPPAbusedTldCatalog {
    <#
    .SYNOPSIS
        Loads the abused-TLD list (Config/AbusedTlds.json) and the shipped TABL templates built from it.
    .DESCRIPTION
        Templates live in Config/TenantAllowBlockListTemplates/AbusedTlds-*.json in exactly the body shape
        AddTenantAllowBlockListTemplate stores (entries, listType, listMethod, notes, NoExpiration, RemoveAfter,
        templateName) plus a fixed GUID and a description, so they can be imported as-is.
        Aspendora fork addition (Vikunja CIPP-30).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([string]$ConfigRoot = (Join-Path $env:CIPPRootPath 'Config'))

    $List = [System.IO.File]::ReadAllText((Join-Path $ConfigRoot 'AbusedTlds.json')) | ConvertFrom-Json
    $Templates = @(Get-ChildItem -Path (Join-Path $ConfigRoot 'TenantAllowBlockListTemplates') -Filter 'AbusedTlds-*.json' -File | Sort-Object Name | ForEach-Object {
            [System.IO.File]::ReadAllText($_.FullName) | ConvertFrom-Json
        })
    [pscustomobject]@{
        Version   = $List.version
        Sources   = @($List.sources)
        Tlds      = @($List.tlds)
        Templates = $Templates
    }
}
