function Invoke-ExecTeamsPolicyTemplate {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Teams.Config.ReadWrite
    .DESCRIPTION
        Deploys a saved Teams policy template to one or many tenants, then READS EACH
        POLICY BACK and reports per-property whether the write actually landed.

        The read-back is not optional. The Teams ConfigAPI returns 204 on a PUT whether
        or not it applied the change, and CIPP has a documented history of endpoints
        reporting success while writing nothing (ExecEditCAPolicyFull). A deploy that
        trusted the status code could silently leave a whole fleet unconfigured while
        reporting success, so every policy is verified and any property whose readback
        value does not match what was sent is reported as a mismatch.

        Body params:
          TemplateId   (required) - GUID from ListTeamsPolicyTemplates
          TenantFilter (required) - a tenant, an array of tenants, or 'AllTenants'
          PolicyTypes             - restrict the deploy to these types from the template
          WhatIf                  - true to report what WOULD change, writing nothing.
                                    Reads each target policy and diffs it against the
                                    template. Use this first.

        Result shape: one entry per tenant per policy, with Status of
        Applied | NoChange | Mismatch | Failed | WouldChange | WouldNotChange.

    .EXAMPLE
        POST /api/ExecTeamsPolicyTemplate
        { "TemplateId": "<guid>", "TenantFilter": "AllTenants", "WhatIf": true }
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TemplateId = $Request.Body.TemplateId
    $TenantFilter = $Request.Body.TenantFilter
    $PolicyTypes = $Request.Body.PolicyTypes
    $WhatIf = ConvertTo-CIPPBoolean -Value ($Request.Body.WhatIf ?? $Request.Query.WhatIf)

    if (-not $TemplateId) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'TemplateId is required.' }
            })
    }
    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'TenantFilter is required (a tenant, an array, or AllTenants).' }
            })
    }

    try {
        $Table = Get-CippTable -tablename 'templates'
        $Entity = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'TeamsPolicyTemplate' and RowKey eq '$TemplateId'"
        if (-not $Entity) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::NotFound
                    Body       = @{ Results = "No Teams policy template with GUID $TemplateId." }
                })
        }
        $Template = $Entity.JSON | ConvertFrom-Json

        $Policies = @($Template.policies)
        if ($PolicyTypes) { $Policies = $Policies | Where-Object { $_.PolicyType -in @($PolicyTypes) } }
        if ($Policies.Count -eq 0) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{ Results = 'No policies to deploy after filtering.' }
                })
        }

        # Resolve the target tenant list.
        $Tenants = if ($TenantFilter -eq 'AllTenants') {
            (Get-Tenants).defaultDomainName
        } else {
            @($TenantFilter)
        }

        $FederationTypes = @('TenantFederationSettings', 'TenantFederationConfiguration', 'TeamsAcsFederationConfiguration')
        $Results = [System.Collections.Generic.List[object]]::new()

        foreach ($Tenant in $Tenants) {
            foreach ($Policy in $Policies) {
                $Type = $Policy.PolicyType
                $PolicyIdentity = $Policy.Identity ?? 'Global'
                $Normalized = $Type -replace '^(Get|Set|New|Remove|Grant|Revoke)-Cs', ''

                $Desired = @{}
                foreach ($Prop in $Policy.Parameters.PSObject.Properties) { $Desired[$Prop.Name] = $Prop.Value }

                $BaseSplat = @{ TenantFilter = $Tenant; Type = $Type; Identity = $PolicyIdentity }
                if ($Normalized -in $FederationTypes) { $BaseSplat.UseServiceDiscovery = $true }

                try {
                    # Read current state first — needed for both the WhatIf diff and to
                    # decide whether anything actually has to change.
                    $Current = New-TeamsRequestV2 @BaseSplat -Action Get

                    $Differences = [System.Collections.Generic.List[object]]::new()
                    foreach ($Key in $Desired.Keys) {
                        $CurrentValue = $Current.$Key
                        if ((ConvertTo-Json $CurrentValue -Depth 10 -Compress) -ne (ConvertTo-Json $Desired[$Key] -Depth 10 -Compress)) {
                            $Differences.Add([pscustomobject]@{ Property = $Key; Current = $CurrentValue; Desired = $Desired[$Key] })
                        }
                    }

                    if ($Differences.Count -eq 0) {
                        $Results.Add([pscustomobject]@{
                                Tenant = $Tenant; PolicyType = $Normalized; Identity = $PolicyIdentity
                                Status = $WhatIf ? 'WouldNotChange' : 'NoChange'
                                Changed = @(); Mismatches = @(); Error = $null
                            })
                        continue
                    }

                    if ($WhatIf) {
                        $Results.Add([pscustomobject]@{
                                Tenant = $Tenant; PolicyType = $Normalized; Identity = $PolicyIdentity
                                Status = 'WouldChange'
                                Changed = @($Differences); Mismatches = @(); Error = $null
                            })
                        continue
                    }

                    # Write only the properties that actually differ. Set is a merge, so
                    # sending the whole body would be noise in the audit log.
                    $ChangeSet = @{}
                    foreach ($Diff in $Differences) { $ChangeSet[$Diff.Property] = $Diff.Desired }
                    $null = New-TeamsRequestV2 @BaseSplat -Action Set -Parameters $ChangeSet

                    # MANDATORY read-back. A 204 proves nothing.
                    $After = New-TeamsRequestV2 @BaseSplat -Action Get
                    $Mismatches = [System.Collections.Generic.List[object]]::new()
                    foreach ($Key in $ChangeSet.Keys) {
                        if ((ConvertTo-Json $After.$Key -Depth 10 -Compress) -ne (ConvertTo-Json $ChangeSet[$Key] -Depth 10 -Compress)) {
                            $Mismatches.Add([pscustomobject]@{ Property = $Key; Expected = $ChangeSet[$Key]; Actual = $After.$Key })
                        }
                    }

                    $Status = $Mismatches.Count -gt 0 ? 'Mismatch' : 'Applied'
                    $Results.Add([pscustomobject]@{
                            Tenant = $Tenant; PolicyType = $Normalized; Identity = $PolicyIdentity
                            Status = $Status
                            Changed = @($ChangeSet.Keys); Mismatches = @($Mismatches); Error = $null
                        })

                    $Sev = $Mismatches.Count -gt 0 ? 'Warn' : 'Info'
                    Write-LogMessage -headers $Headers -API $APIName -tenant $Tenant -Sev $Sev `
                        -message "Teams template '$($Template.name)': $Status on $Normalized/$PolicyIdentity ($(($ChangeSet.Keys | Sort-Object) -join ', '))"
                } catch {
                    $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                    $Results.Add([pscustomobject]@{
                            Tenant = $Tenant; PolicyType = $Normalized; Identity = $PolicyIdentity
                            Status = 'Failed'; Changed = @(); Mismatches = @(); Error = $ErrorMessage
                        })
                    Write-LogMessage -headers $Headers -API $APIName -tenant $Tenant -Sev 'Error' `
                        -message "Teams template '$($Template.name)' failed on $Normalized/$PolicyIdentity - $ErrorMessage"
                }
            }
        }

        $Summary = $Results | Group-Object Status | ForEach-Object { "$($_.Name)=$($_.Count)" }
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results  = "Template '$($Template.name)' across $($Tenants.Count) tenant(s): $($Summary -join ', ')"
                    WhatIf   = $WhatIf
                    Details  = @($Results)
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to deploy Teams policy template: $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -message $Result -Sev 'Error' -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = $Result }
            })
    }
}
