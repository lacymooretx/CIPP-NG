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
    if ($Type -notin @('Scripts', 'Policies')) {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = "Invalid Type '$Type'. Allowed: Scripts, Policies." } })
    }

    $GraphBeta = 'https://graph.microsoft.com/beta'

    try {
        $Notes = [System.Collections.Generic.List[string]]::new()

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
