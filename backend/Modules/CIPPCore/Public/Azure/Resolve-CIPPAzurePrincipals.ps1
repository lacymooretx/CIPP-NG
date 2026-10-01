function Resolve-CIPPAzurePrincipals {
    <#
    .SYNOPSIS
        Resolves Azure RBAC principal ids to directory objects in one tenant
    .DESCRIPTION
        Returns a hashtable keyed by object id. An id missing from the result was not found in the
        directory: a deleted principal (orphaned assignment) or a foreign principal from another tenant.
        `external` is true for guest users and for service principals owned by another organisation
        (Microsoft's own first-party apps excluded).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [string[]]$PrincipalIds
    )

    $Result = @{}
    $Ids = @($PrincipalIds | Where-Object { $_ } | Sort-Object -Unique)
    if ($Ids.Count -eq 0) { return $Result }

    $TenantId = (Get-Tenants -TenantFilter $TenantFilter -IncludeErrors | Select-Object -First 1).customerId
    $MicrosoftTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

    for ($i = 0; $i -lt $Ids.Count; $i += 1000) {
        $Chunk = $Ids[$i..([Math]::Min($i + 999, $Ids.Count - 1))]
        $Body = @{ ids = @($Chunk); types = @('user', 'group', 'servicePrincipal') } | ConvertTo-Json -Compress
        $Response = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' -tenantid $TenantFilter -body $Body -AsApp $true
        foreach ($Obj in @($Response.value)) {
            $ObjectType = ([string]$Obj.'@odata.type').Replace('#microsoft.graph.', '')
            $External = switch ($ObjectType) {
                'user' { $Obj.userType -eq 'Guest' }
                'servicePrincipal' {
                    $Owner = [string]$Obj.appOwnerOrganizationId
                    [bool]($Owner -and $TenantId -and $Owner -ne $TenantId -and $MicrosoftTenants -notcontains $Owner)
                }
                default { $false }
            }
            $Result[[string]$Obj.id] = [pscustomobject]@{
                displayName          = $Obj.displayName
                userPrincipalName    = $Obj.userPrincipalName
                userType             = $Obj.userType
                objectType           = $ObjectType
                servicePrincipalType = $Obj.servicePrincipalType
                external             = $External
            }
        }
    }
    $Result
}
