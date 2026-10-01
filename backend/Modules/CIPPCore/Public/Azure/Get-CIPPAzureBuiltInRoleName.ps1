function Get-CIPPAzureBuiltInRoleName {
    <#
    .SYNOPSIS
        Name of a well-known built-in Azure role from its definition GUID
    .DESCRIPTION
        Fallback for assignments whose role name Resource Graph didn't join (PIM-eligible rows, or a
        tenant where built-in definitions aren't surfaced). Built-in role GUIDs are identical in every
        tenant. Returns $null for anything not in the list.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([string]$RoleDefinitionGuid)

    $Known = @{
        '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
        'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
        'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
        '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
        'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
        'fb1c8493-542b-48eb-b624-b4c8fea62acd' = 'Security Admin'
        '39bc4728-0917-49c7-9d2c-d95423bc2eb4' = 'Security Reader'
        '00482a5a-887f-4fb3-b363-3b7fe8e74483' = 'Key Vault Administrator'
        'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' = 'Key Vault Secrets Officer'
        '9980e02c-c2be-4d73-94e8-173b1dc7cf3c' = 'Virtual Machine Contributor'
        '1c0163c0-47e6-4577-8991-ea5c82e286e4' = 'Virtual Machine Administrator Login'
        '17d1049b-9a84-46fb-8f53-869881c3d3ab' = 'Storage Account Contributor'
        'b7e6dc6d-f1e8-4753-8033-0f276bb0955b' = 'Storage Blob Data Owner'
        '4d97b98b-1d4f-4787-a291-c67834d212e7' = 'Network Contributor'
    }
    if ($RoleDefinitionGuid) { $Known[$RoleDefinitionGuid.ToLower()] } else { $null }
}
