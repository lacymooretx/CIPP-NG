function Invoke-ListPolicyTargets {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Reverse assignment lookup: given a device, user or group, returns every Intune policy that
        targets it, and whether an exclusion cancels that targeting.

        CIPP can already answer "what does this policy target". This answers the inverse - "what
        lands on this object" - which is the question asked when a device behaves unexpectedly, and
        the one that previously required reading every policy's assignments by hand.

        Matching covers all four target forms Intune actually uses:
          - group assignment, matched on the object's TRANSITIVE group membership, so a policy
            assigned to a parent group is found even though the object is only a nested member
          - All Devices / All Users / All Licensed Users virtual targets, applied only to the object
            type they can apply to
          - the exclusion forms of each, which cancel an include

        EXCLUSION WINS. Intune resolves an exclusion over an include, so a policy that is both
        included and excluded is reported as NOT effective. It is still listed, with both reasons,
        because "assigned but excluded" is a different problem from "not assigned" and silently
        dropping it hides the more confusing of the two.

        Parameters (query or body):
          TenantFilter (required)
          DeviceId   - Intune managedDevice id, or the Entra device object id
          UserId     - Entra user object id or UPN
          GroupId    - Entra group object id
        Exactly one of DeviceId / UserId / GroupId is required.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Query.TenantFilter ?? $Request.Body.TenantFilter
    $DeviceId = $Request.Query.DeviceId ?? $Request.Body.DeviceId
    $UserId = $Request.Query.UserId ?? $Request.Body.UserId
    $GroupId = $Request.Query.GroupId ?? $Request.Body.GroupId

    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'TenantFilter is required.' } })
    }
    $Supplied = @($DeviceId, $UserId, $GroupId | Where-Object { $_ })
    if ($Supplied.Count -ne 1) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Supply exactly one of DeviceId, UserId or GroupId.' } })
    }

    try {
        # --- Resolve the object and the groups it belongs to -----------------------------------
        $ObjectType = if ($DeviceId) { 'Device' } elseif ($UserId) { 'User' } else { 'Group' }
        $ObjectName = $null
        $GroupIds = [System.Collections.Generic.HashSet[string]]::new()

        switch ($ObjectType) {
            'Device' {
                # A managedDevice id is not a directory object id. Group membership lives on the
                # Entra device, so the Intune record has to be translated first - matching on the
                # managedDevice id alone would silently find no groups.
                $DirectoryId = $null
                try {
                    $Managed = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$DeviceId`?`$select=id,deviceName,azureADDeviceId" -tenantid $TenantFilter
                    $ObjectName = $Managed.deviceName
                    if ($Managed.azureADDeviceId) {
                        $Entra = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/devices?`$filter=deviceId eq '$($Managed.azureADDeviceId)'&`$select=id,displayName" -tenantid $TenantFilter)
                        $DirectoryId = $Entra[0].id
                    }
                } catch {
                    # Not an Intune managedDevice id - treat the value as an Entra device object id.
                    $DirectoryId = $DeviceId
                }
                if (-not $DirectoryId) { $DirectoryId = $DeviceId }
                if (-not $ObjectName) {
                    try { $ObjectName = (New-GraphGetRequest -uri "https://graph.microsoft.com/beta/devices/$DirectoryId`?`$select=displayName" -tenantid $TenantFilter).displayName } catch {}
                }
                foreach ($G in @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/devices/$DirectoryId/transitiveMemberOf?`$select=id" -tenantid $TenantFilter)) {
                    if ($G.id) { $null = $GroupIds.Add([string]$G.id) }
                }
            }
            'User' {
                $User = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/users/$UserId`?`$select=id,displayName,userPrincipalName" -tenantid $TenantFilter
                $ObjectName = $User.userPrincipalName ?? $User.displayName
                foreach ($G in @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/users/$($User.id)/transitiveMemberOf?`$select=id" -tenantid $TenantFilter)) {
                    if ($G.id) { $null = $GroupIds.Add([string]$G.id) }
                }
            }
            'Group' {
                $Group = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/groups/$GroupId`?`$select=id,displayName" -tenantid $TenantFilter
                $ObjectName = $Group.displayName
                # A policy assigned to this group targets it directly. Nested PARENT groups also
                # carry down to its members, so they count as targeting this group's members too.
                $null = $GroupIds.Add([string]$Group.id)
                try {
                    foreach ($G in @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/groups/$($Group.id)/transitiveMemberOf?`$select=id" -tenantid $TenantFilter)) {
                        if ($G.id) { $null = $GroupIds.Add([string]$G.id) }
                    }
                } catch {}
            }
        }

        # --- Gather every policy with its assignments ------------------------------------------
        $Definitions = @(Get-CIPPIntunePolicyListDefinitions)
        $BulkRequests = [System.Collections.Generic.List[object]]::new()
        $BulkRequests.Add([PSCustomObject]@{ id = 'Groups'; method = 'GET'; url = '/groups?$top=999&$select=id,displayName' })
        foreach ($Definition in $Definitions) {
            $BulkRequests.Add([PSCustomObject]@{ id = $Definition.Id; method = 'GET'; url = $Definition.GraphUri })
        }
        $BulkResults = New-GraphBulkRequest -Requests @($BulkRequests) -tenantid $TenantFilter

        $GroupLookup = @{}
        $GroupResult = $BulkResults | Where-Object { $_.id -eq 'Groups' } | Select-Object -First 1
        foreach ($G in @($GroupResult.body.value)) { if ($G.id) { $GroupLookup[[string]$G.id] = $G.displayName } }

        # Virtual targets only apply to the object type they can apply to. A policy assigned to
        # All Users does not land on a device, and reporting it would be a false positive.
        $AppliesToDevice = $ObjectType -eq 'Device'
        $AppliesToUser = $ObjectType -eq 'User'

        $Results = [System.Collections.Generic.List[object]]::new()

        foreach ($Definition in $Definitions) {
            $Result = $BulkResults | Where-Object { $_.id -eq $Definition.Id } | Select-Object -First 1
            if (-not $Result) { continue }
            if ($null -ne $Result.status -and ($Result.status -lt 200 -or $Result.status -ge 300)) { continue }

            foreach ($Policy in @($Result.body.value)) {
                if ($null -eq $Policy) { continue }

                $IncludeReasons = [System.Collections.Generic.List[string]]::new()
                $ExcludeReasons = [System.Collections.Generic.List[string]]::new()

                foreach ($Assignment in @($Policy.assignments)) {
                    $Target = $Assignment.target
                    if (-not $Target) { continue }
                    $TargetGroupId = [string]$Target.groupId
                    $TargetGroupName = if ($TargetGroupId -and $GroupLookup.ContainsKey($TargetGroupId)) { $GroupLookup[$TargetGroupId] } else { $TargetGroupId }

                    switch ($Target.'@odata.type') {
                        '#microsoft.graph.groupAssignmentTarget' {
                            if ($TargetGroupId -and $GroupIds.Contains($TargetGroupId)) { $IncludeReasons.Add("Group: $TargetGroupName") }
                        }
                        '#microsoft.graph.exclusionGroupAssignmentTarget' {
                            if ($TargetGroupId -and $GroupIds.Contains($TargetGroupId)) { $ExcludeReasons.Add("Excluded group: $TargetGroupName") }
                        }
                        '#microsoft.graph.allDevicesAssignmentTarget' {
                            if ($AppliesToDevice) { $IncludeReasons.Add('All Devices') }
                        }
                        '#microsoft.graph.exclusionallDevicesAssignmentTarget' {
                            if ($AppliesToDevice) { $ExcludeReasons.Add('Excluded: All Devices') }
                        }
                        '#microsoft.graph.allUsersAssignmentTarget' {
                            if ($AppliesToUser) { $IncludeReasons.Add('All Users') }
                        }
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                            if ($AppliesToUser) { $IncludeReasons.Add('All Licensed Users') }
                        }
                        '#microsoft.graph.exclusionallUsersAssignmentTarget' {
                            if ($AppliesToUser) { $ExcludeReasons.Add('Excluded: All Users') }
                        }
                    }
                }

                if ($IncludeReasons.Count -eq 0 -and $ExcludeReasons.Count -eq 0) { continue }

                $PolicyName = $Policy.displayName ?? $Policy.name
                $Results.Add([PSCustomObject]@{
                        PolicyName    = [string]$PolicyName
                        PolicyType    = [string]($Definition.PolicyTypeName ?? $Definition.Id)
                        PolicyId      = [string]$Policy.id
                        Family        = [string]$Definition.Id
                        MatchedVia    = ($IncludeReasons -join ', ')
                        ExcludedVia   = ($ExcludeReasons -join ', ')
                        # Intune resolves an exclusion over an include.
                        Effective     = ($IncludeReasons.Count -gt 0 -and $ExcludeReasons.Count -eq 0)
                        Status        = if ($ExcludeReasons.Count -gt 0 -and $IncludeReasons.Count -gt 0) { 'Excluded (assigned but cancelled)' }
                                        elseif ($ExcludeReasons.Count -gt 0) { 'Excluded only' }
                                        else { 'Applies' }
                    })
            }
        }

        $Body = @{
            Results  = @($Results | Sort-Object @{ Expression = { -not $_.Effective } }, PolicyType, PolicyName)
            Metadata = @{
                ObjectType   = $ObjectType
                ObjectName   = $ObjectName
                GroupCount   = $GroupIds.Count
                PolicyCount  = $Results.Count
                EffectiveCount = @($Results | Where-Object { $_.Effective }).Count
            }
        }
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Policy target lookup failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $Body = @{ Results = "Failed to resolve policy targets: $($ErrorMessage.NormalizedError)" }
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
