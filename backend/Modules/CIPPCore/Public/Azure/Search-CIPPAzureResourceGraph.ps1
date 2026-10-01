function Search-CIPPAzureResourceGraph {
    <#
    .SYNOPSIS
        Run an Azure Resource Graph (KQL) query in a client tenant, following $skipToken paging
    .DESCRIPTION
        One query spans every subscription the CIPP-SAM principal can read in that tenant, which is
        what makes Resource Graph the backbone of the Azure compliance collectors. Results come back
        as an object array.
    .PARAMETER TenantFilter
        Tenant default domain or id.
    .PARAMETER Query
        KQL query, e.g. "resources | where type =~ 'microsoft.storage/storageaccounts'".
    .PARAMETER Subscriptions
        Optional subscription ids to scope the query to. Omit to query every readable subscription.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$Query,

        [string[]]$Subscriptions
    )

    $Uri = '/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01'
    $SkipToken = $null
    do {
        $Options = @{ resultFormat = 'objectArray'; '$top' = 1000 }
        if ($SkipToken) { $Options['$skipToken'] = $SkipToken }
        $Body = @{ query = $Query; options = $Options }
        if ($Subscriptions) { $Body.subscriptions = @($Subscriptions) }

        $Response = New-CIPPAzureRequest -TenantFilter $TenantFilter -Uri $Uri -Method POST -Body $Body -Raw
        foreach ($Row in @($Response.data)) { $Row }
        $SkipToken = $Response.'$skipToken'
    } while ($SkipToken)
}
