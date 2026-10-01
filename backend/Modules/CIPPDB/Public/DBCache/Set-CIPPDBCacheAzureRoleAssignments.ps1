function Set-CIPPDBCacheAzureRoleAssignments {
    <#
    .SYNOPSIS
        Caches Azure RBAC role assignments (active and PIM-eligible) with role and principal names resolved
    .DESCRIPTION
        Active assignments come from Resource Graph; PIM-eligible ones from ARM per subscription
        (Resource Graph doesn't carry eligibility schedules). Role names are joined from the
        roledefinitions table. Principals are resolved through Graph directoryObjects/getByIds so the
        tests can tell guests, external service principals and deleted (orphaned) principals apart.
    .PARAMETER TenantFilter
        The tenant to cache Azure role assignments for
    .PARAMETER QueueId
        The queue ID to update with total tasks (optional)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string]$QueueId
    )

    $Query = @'
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend roleDefinitionGuid = tolower(tostring(split(tostring(properties.roleDefinitionId), '/')[-1]))
| join kind=leftouter (
    authorizationresources
    | where type =~ 'microsoft.authorization/roledefinitions'
    | project roleDefinitionGuid = tolower(name), roleName = tostring(properties.roleName), roleType = tostring(properties.type)
    | summarize roleName = take_any(roleName), roleType = take_any(roleType) by roleDefinitionGuid
) on roleDefinitionGuid
| project id, subscriptionId, scope = tostring(properties.scope), principalId = tostring(properties.principalId),
    principalType = tostring(properties.principalType), roleDefinitionGuid, roleName, roleType,
    condition = tostring(properties.condition), createdOn = tostring(properties.createdOn)
'@

    try {
        Set-CIPPAzureCacheItems -TenantFilter $TenantFilter -Type 'AzureRoleAssignments' -ScriptBlock {
            param($SubscriptionIds)

            $Assignments = [System.Collections.Generic.List[object]]::new()
            foreach ($Row in @(Search-CIPPAzureResourceGraph -TenantFilter $TenantFilter -Query $Query -Subscriptions $SubscriptionIds)) {
                $Row | Add-Member -NotePropertyName assignmentState -NotePropertyValue 'Active' -Force
                $Assignments.Add($Row)
            }

            foreach ($SubscriptionId in $SubscriptionIds) {
                try {
                    $Eligible = New-CIPPAzureRequest -TenantFilter $TenantFilter -Uri "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01"
                    foreach ($E in @($Eligible)) {
                        $Assignments.Add([pscustomobject]@{
                                id                 = $E.id
                                subscriptionId     = $SubscriptionId
                                scope              = $E.properties.scope
                                principalId        = $E.properties.principalId
                                principalType      = $E.properties.principalType
                                roleDefinitionGuid = ([string]$E.properties.roleDefinitionId).Split('/')[-1].ToLower()
                                roleName           = $null
                                roleType           = $null
                                condition          = $E.properties.condition
                                createdOn          = $E.properties.startDateTime
                                assignmentState    = 'Eligible'
                            })
                    }
                } catch {
                    Write-Information "[AzureRoleAssignments] Eligible assignments unavailable for $SubscriptionId on $TenantFilter : $($_.Exception.Message)"
                }
            }

            # Resource Graph only joins custom roles, and eligible rows have no join at all. Fill the rest
            # from a known-name table, then ARM (once per role), so every row carries a role name.
            $RoleNames = @{}
            foreach ($A in $Assignments) { if ($A.roleName) { $RoleNames[$A.roleDefinitionGuid] = $A.roleName } }
            foreach ($A in $Assignments) {
                if ($A.roleName) { continue }
                if (-not $RoleNames.ContainsKey($A.roleDefinitionGuid)) {
                    $Name = Get-CIPPAzureBuiltInRoleName -RoleDefinitionGuid $A.roleDefinitionGuid
                    if (-not $Name) {
                        try {
                            $Name = (New-CIPPAzureRequest -TenantFilter $TenantFilter -Uri "/subscriptions/$($A.subscriptionId)/providers/Microsoft.Authorization/roleDefinitions/$($A.roleDefinitionGuid)?api-version=2022-04-01").properties.roleName
                        } catch {
                            Write-Information "[AzureRoleAssignments] Could not resolve role $($A.roleDefinitionGuid): $($_.Exception.Message)"
                        }
                    }
                    $RoleNames[$A.roleDefinitionGuid] = $Name
                }
                $A.roleName = $RoleNames[$A.roleDefinitionGuid]
            }

            $Principals = Resolve-CIPPAzurePrincipals -TenantFilter $TenantFilter -PrincipalIds @($Assignments.principalId)
            foreach ($A in $Assignments) {
                $P = $Principals[[string]$A.principalId]
                $A | Add-Member -NotePropertyName principalResolved -NotePropertyValue ([bool]$P) -Force
                $A | Add-Member -NotePropertyName principalDisplayName -NotePropertyValue $P.displayName -Force
                $A | Add-Member -NotePropertyName principalUpn -NotePropertyValue $P.userPrincipalName -Force
                $A | Add-Member -NotePropertyName principalUserType -NotePropertyValue $P.userType -Force
                $A | Add-Member -NotePropertyName principalObjectType -NotePropertyValue $P.objectType -Force
                $A | Add-Member -NotePropertyName principalExternal -NotePropertyValue ([bool]$P.external) -Force
                $A
            }
        }
    } catch {
        Write-LogMessage -API 'CIPPDBCache' -tenant $TenantFilter -message "Failed to cache Azure role assignments: $($_.Exception.Message)" -sev Error
        throw
    }
}
