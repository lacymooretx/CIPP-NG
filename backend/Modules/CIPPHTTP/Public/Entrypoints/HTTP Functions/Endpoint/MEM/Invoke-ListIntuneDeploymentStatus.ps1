function Invoke-ListIntuneDeploymentStatus {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Returns deployment outcome counts for Intune remediation scripts and device configuration
        profiles, in one bulk call per type, so a list view can show "is this actually working"
        instead of only "does this exist".

        Type=Scripts   - remediation (deviceHealthScripts) run summaries: how many devices had an
                         issue detected, how many were remediated, and how many failed either the
                         detection or the remediation script. CIPP could already list health
                         scripts but never their results.
        Type=Policies  - deviceConfiguration deviceStatusOverview: success / error / conflict /
                         pending / not-applicable counts per profile.
        Type=FeatureUpdates - per-device alerts against each Windows Feature Update profile, via the
                         Intune reports surface. The obvious endpoint,
                         windowsFeatureUpdateProfiles/{id}/deviceUpdateStates, DOES NOT EXIST - the
                         $expand form says so outright ("Could not find a property named
                         'deviceUpdateStates' on type 'microsoft.graph.windowsFeatureUpdateProfile'").
                         getWindowsUpdateAlertsPerPolicyPerDeviceReport is the real route: a POST,
                         requiring a PolicyId restriction filter, returning a Schema/Values table
                         rather than objects. Reporting ALERTS rather than raw state is also the more
                         useful answer - it names the devices a profile is failing on.

        COVERAGE LIMIT, verified live 2026-09-17 rather than assumed: deviceStatusOverview exists on
        deviceConfigurations but NOT on configurationPolicies - a settings-catalog policy returns
        "Resource not found for the segment 'deviceStatusOverview'". Settings-catalog deployment
        status comes from the Intune reports surface (getConfigurationPolicyReport), which is a
        different and heavier integration. This endpoint therefore covers legacy configuration
        profiles only, and says so rather than silently returning a short list.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Query.TenantFilter ?? $Request.Body.TenantFilter
    $Type = ($Request.Query.Type ?? $Request.Body.Type ?? 'Scripts').ToString()

    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'TenantFilter is required.' } })
    }
    if ($Type -notin @('Scripts', 'Policies', 'FeatureUpdates')) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = "Invalid Type '$Type'. Allowed: Scripts, Policies, FeatureUpdates." } })
    }

    $GraphBeta = 'https://graph.microsoft.com/beta'

    try {
        $Notes = [System.Collections.Generic.List[string]]::new()

        if ($Type -eq 'FeatureUpdates') {
            $Profiles = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/windowsFeatureUpdateProfiles?`$select=id,displayName" -tenantid $TenantFilter)
            if ($Profiles.Count -eq 0) {
                return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = @(); Metadata = @{ Type = $Type; Count = 0; Notes = @('No Windows Feature Update profiles exist in this tenant.') } } })
            }

            $Results = [System.Collections.Generic.List[object]]::new()
            $Unavailable = 0

            foreach ($UpdateProfile in $Profiles) {
                $Name = [string]$UpdateProfile.displayName
                try {
                    # POST, and the PolicyId restriction filter is mandatory - without it the
                    # service answers "One or more required filters are not set".
                    $ReportBody = @{ filter = "(PolicyId eq '$($UpdateProfile.id)')"; top = 500 } | ConvertTo-Json -Compress
                    $Report = New-GraphPOSTRequest -uri "$GraphBeta/deviceManagement/reports/getWindowsUpdateAlertsPerPolicyPerDeviceReport" -tenantid $TenantFilter -type 'POST' -body $ReportBody
                } catch {
                    # Unknown, never zero - zero would read as "no devices are failing".
                    $Unavailable++
                    $Results.Add([PSCustomObject]@{ Id = [string]$UpdateProfile.id; Name = $Name; StatusAvailable = $false })
                    continue
                }

                # Schema/Values is a table: column definitions plus rows as positional arrays.
                $Columns = @($Report.Schema.Column)
                $Devices = [System.Collections.Generic.List[object]]::new()
                # Indexed, NOT `foreach ($Row in @($Report.Values))`. Values is an array of arrays,
                # and wrapping that in @() flattens a single row into its individual cells - the row
                # then reads as N one-cell rows and every field comes out empty.
                $RowCount = if ($null -ne $Report.Values) { @($Report.Values).Count } else { 0 }
                if ($null -ne $Report.Values -and $Report.Values.Count) { $RowCount = $Report.Values.Count }
                for ($rw = 0; $rw -lt $RowCount; $rw++) {
                    $Row = $Report.Values[$rw]
                    $Cells = $Row
                    $Item = @{}
                    for ($i = 0; $i -lt $Columns.Count -and $i -lt $Cells.Count; $i++) { $Item[$Columns[$i]] = $Cells[$i] }
                    $Devices.Add([PSCustomObject]@{
                            DeviceName = [string]$Item['DeviceName']
                            UPN        = [string]$Item['UPN']
                            # The _loc columns carry human-readable text; the bare ones are ids.
                            Alert      = [string]($Item['AlertMessage_loc'] ?? $Item['AlertMessage'])
                            Detail     = [string]($Item['AlertMessageDescription_loc'] ?? $Item['AlertMessageDescription'])
                        })
                }

                $Results.Add([PSCustomObject]@{
                        Id              = [string]$UpdateProfile.id
                        Name            = $Name
                        StatusAvailable = $true
                        AlertCount      = [int]$Report.TotalRowCount
                        # Counted with an explicit loop: member enumeration over a generic List
                        # does not behave like it does over an array, and silently yields nothing.
                        DevicesAffected = $(
                            $Seen = [System.Collections.Generic.HashSet[string]]::new()
                            for ($d = 0; $d -lt $Devices.Count; $d++) {
                                $Dn = [string]$Devices[$d].DeviceName
                                if ($Dn) { $null = $Seen.Add($Dn) }
                            }
                            $Seen.Count
                        )
                        Devices         = $Devices
                        LastUpdated     = [string]$Report.LastUpdatedTime
                        Unhealthy       = ([int]$Report.TotalRowCount -gt 0)
                    })
            }

            $FuNotes = [System.Collections.Generic.List[string]]::new()
            if ($Unavailable -gt 0) { $FuNotes.Add("$Unavailable profile(s) did not return a report and are reported as unknown, not zero.") }

            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = @{
                        Results  = @($Results | Sort-Object @{ Expression = { -not $_.Unhealthy } }, Name)
                        Metadata = @{
                            Type           = $Type
                            Count          = $Results.Count
                            UnhealthyCount = @($Results | Where-Object { $_.Unhealthy }).Count
                            Unavailable    = $Unavailable
                            Notes          = @($FuNotes)
                        }
                    }
                })
        }

        if ($Type -eq 'Scripts') {
            $Parents = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/deviceHealthScripts?`$select=id,displayName,publisher" -tenantid $TenantFilter)
            $SubPath = 'runSummary'
            $Collection = 'deviceHealthScripts'
        } else {
            $Parents = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/deviceConfigurations?`$select=id,displayName&`$top=999" -tenantid $TenantFilter)
            $SubPath = 'deviceStatusOverview'
            $Collection = 'deviceConfigurations'
            $Notes.Add('Settings-catalog policies (configurationPolicies) are not included: Graph does not expose deviceStatusOverview on that type.')
        }

        if ($Parents.Count -eq 0) {
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = @{ Results = @(); Metadata = @{ Type = $Type; Count = 0; Notes = @($Notes) } } })
        }

        # One request per parent, batched. Sequential calls would be one round trip per policy.
        $BulkRequests = [System.Collections.Generic.List[object]]::new()
        foreach ($Parent in $Parents) {
            $BulkRequests.Add([PSCustomObject]@{ id = [string]$Parent.id; method = 'GET'; url = "/deviceManagement/$Collection/$($Parent.id)/$SubPath" })
        }
        $BulkResults = New-GraphBulkRequest -Requests @($BulkRequests) -tenantid $TenantFilter

        $Results = [System.Collections.Generic.List[object]]::new()
        $Unavailable = 0

        foreach ($Parent in $Parents) {
            $Result = $BulkResults | Where-Object { $_.id -eq [string]$Parent.id } | Select-Object -First 1
            $Ok = $Result -and ($null -eq $Result.status -or ($Result.status -ge 200 -and $Result.status -lt 300))
            $Name = [string]($Parent.displayName ?? $Parent.name)

            if (-not $Ok) {
                # A parent whose status cannot be read is reported as unknown rather than zero.
                # Zero would read as "deployed everywhere successfully", which is the opposite.
                $Unavailable++
                $Results.Add([PSCustomObject]@{ Id = [string]$Parent.id; Name = $Name; StatusAvailable = $false })
                continue
            }

            $S = $Result.body
            if ($Type -eq 'Scripts') {
                $Failed = [int]$S.detectionScriptErrorDeviceCount + [int]$S.remediationScriptErrorDeviceCount
                $Results.Add([PSCustomObject]@{
                        Id                  = [string]$Parent.id
                        Name                = $Name
                        Publisher           = [string]$Parent.publisher
                        StatusAvailable     = $true
                        NoIssueDetected     = [int]$S.noIssueDetectedDeviceCount
                        IssueDetected       = [int]$S.issueDetectedDeviceCount
                        IssueRemediated     = [int]$S.issueRemediatedDeviceCount
                        IssueReoccurred     = [int]$S.issueReoccurredDeviceCount
                        DetectionFailed     = [int]$S.detectionScriptErrorDeviceCount
                        RemediationFailed   = [int]$S.remediationScriptErrorDeviceCount
                        ScriptErrors        = $Failed
                        # Unhealthy = the script itself is broken, which is different from the
                        # script correctly finding an issue on a device.
                        Unhealthy           = ($Failed -gt 0)
                    })
            } else {
                $Results.Add([PSCustomObject]@{
                        Id              = [string]$Parent.id
                        Name            = $Name
                        StatusAvailable = $true
                        Success         = [int]$S.successCount
                        Error           = [int]$S.errorCount
                        Conflict        = [int]$S.conflictCount
                        Pending         = [int]$S.pendingCount
                        NotApplicable   = [int]$S.notApplicableCount
                        Failing         = ([int]$S.errorCount + [int]$S.conflictCount)
                        Unhealthy       = (([int]$S.errorCount + [int]$S.conflictCount) -gt 0)
                    })
            }
        }

        if ($Unavailable -gt 0) { $Notes.Add("$Unavailable item(s) did not return a status and are reported as unknown, not zero.") }

        $Body = @{
            Results  = @($Results | Sort-Object @{ Expression = { -not $_.Unhealthy } }, Name)
            Metadata = @{
                Type           = $Type
                Count          = $Results.Count
                UnhealthyCount = @($Results | Where-Object { $_.Unhealthy }).Count
                Unavailable    = $Unavailable
                Notes          = @($Notes)
            }
        }
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Intune deployment status lookup failed: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $Body = @{ Results = "Failed to read deployment status: $($ErrorMessage.NormalizedError)" }
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
