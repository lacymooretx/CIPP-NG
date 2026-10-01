function Get-CippAzureResourcesOfType {
    <#
    .SYNOPSIS
        Resources of one or more (lower-case) types from an Azure test context
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string[]]$Type
    )
    foreach ($T in $Type) {
        if ($Context.ByType.ContainsKey($T.ToLower())) { $Context.ByType[$T.ToLower()] }
    }
}
