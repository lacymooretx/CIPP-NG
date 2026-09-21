using namespace System.Net

function Invoke-ExecCloudPCProvisioningPolicyAssign {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    .DESCRIPTION
        Assigns a Windows 365 provisioning policy to one or more Entra groups.

        THE THING TO UNDERSTAND BEFORE CHANGING THIS: Graph's
        POST provisioningPolicies/{id}/assign is REPLACE-mode. The assignments array you send
        becomes the entire assignment set - anything omitted is unassigned. Sending one group to a
        policy that already serves five detaches the other four, and detaching a provisioning
        policy from the group whose users own Cloud PCs is not a paperwork change.

        So this endpoint defaults to ADD, not replace: it reads the current assignments and sends
        their union with the requested groups. Replace is available but must be asked for by name,
        and clearing every assignment additionally requires AllowRemoveAll - because
        'Replace with an empty list' is indistinguishable, in a request body, from a caller whose
        GroupIds array failed to serialize.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $PolicyId = $Request.Body.PolicyId ?? $Request.Query.PolicyId
    $RequestedGroups = @($Request.Body.GroupIds | Where-Object { $_ })
    $AssignmentMode = ($Request.Body.AssignmentMode ?? 'Add').ToString()
    $AllowRemoveAll = ConvertTo-CIPPBoolean -Value $Request.Body.AllowRemoveAll

    try {
        if ([string]::IsNullOrWhiteSpace($TenantFilter)) { throw 'tenantFilter is required.' }
        if ([string]::IsNullOrWhiteSpace($PolicyId)) { throw 'PolicyId is required.' }
        if ($AssignmentMode -notin @('Add', 'Replace')) {
            throw "Invalid AssignmentMode '$AssignmentMode'. Allowed: Add (default, keeps existing assignments), Replace (discards them)."
        }

        # Current state first - both modes need it: Add unions with it, Replace reports what it drops.
        $Existing = @((New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies/$PolicyId`?`$expand=assignments" -tenantid $TenantFilter -AsApp $true -ErrorAction Stop).assignments)
        $ExistingGroups = @($Existing.target.groupId | Where-Object { $_ })

        $FinalGroups = if ($AssignmentMode -eq 'Replace') {
            @($RequestedGroups)
        } else {
            @(@($ExistingGroups) + @($RequestedGroups) | Where-Object { $_ } | Select-Object -Unique)
        }

        if ($AssignmentMode -eq 'Replace') {
            $Removing = @($ExistingGroups | Where-Object { $_ -notin $FinalGroups })
            if ($FinalGroups.Count -eq 0 -and -not $AllowRemoveAll) {
                throw "Replace with no GroupIds would unassign this policy from every group ($($ExistingGroups.Count) currently assigned). If that is intended, resend with AllowRemoveAll=true."
            }
            if ($Removing.Count -gt 0) {
                Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Cloud PC policy $PolicyId : Replace mode is removing $($Removing.Count) existing assignment(s): $($Removing -join ', ')" -Sev 'Warn'
            }
        }

        if ($AssignmentMode -eq 'Add' -and $RequestedGroups.Count -eq 0) {
            throw 'GroupIds is required when AssignmentMode is Add.'
        }

        $AssignBody = @{
            assignments = @(
                foreach ($GroupId in $FinalGroups) {
                    @{
                        target = @{
                            '@odata.type' = '#microsoft.graph.cloudPcManagementGroupAssignmentTarget'
                            groupId       = $GroupId
                        }
                    }
                }
            )
        } | ConvertTo-Json -Depth 10 -Compress

        $null = New-GraphPOSTRequest -uri "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies/$PolicyId/assign" -tenantid $TenantFilter -body $AssignBody -AsApp $true -ErrorAction Stop

        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Assigned Cloud PC provisioning policy $PolicyId to $($FinalGroups.Count) group(s) (mode: $AssignmentMode, was $($ExistingGroups.Count))" -Sev 'Info'

        $Body = [PSCustomObject]@{
            Results = "Policy assigned to $($FinalGroups.Count) group(s). Previously $($ExistingGroups.Count). Mode: $AssignmentMode."
            AssignedGroups = @($FinalGroups)
            PreviousGroups = @($ExistingGroups)
            Mode           = $AssignmentMode
        }
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Cloud PC policy assignment failed: $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
        $Body = [PSCustomObject]@{ Results = "Failed to assign policy: $($ErrorMessage.NormalizedError)" }
        $StatusCode = [HttpStatusCode]::BadRequest
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
