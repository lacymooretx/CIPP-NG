# Deployment outcome counts for remediation scripts (A5) and configuration profiles (B1).
#
# The assertion that matters most: an item whose status cannot be READ is reported as unknown, never
# as zero. Zero reads as "deployed everywhere successfully", which is the exact opposite of the
# truth, and is the same silent-false-success class as the rest of this session's findings.
#
# For scripts, "unhealthy" means the SCRIPT is broken (detection or remediation errored), which is a
# different thing from the script correctly detecting an issue on a device. Conflating them would
# make every working remediation script look broken.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/MEM/Invoke-ListIntuneDeploymentStatus.ps1'

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext { [int]$StatusCode; [object]$Body }

    function New-GraphGetRequest { param($uri, $tenantid) return $script:Parents }
    function New-GraphPOSTRequest {
        param($uri, $tenantid, $type, $body)
        $script:LastReportBody = $body
        if ($script:ReportThrows) { throw 'report unavailable' }
        return $script:Report
    }
    function New-GraphBulkRequest { param($Requests, $tenantid) return $script:BulkResults }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) $script:Logs += $message }
    function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }

    . $FunctionPath

    function Invoke-Status { param($Type = 'Scripts')
        Invoke-ListIntuneDeploymentStatus -Request ([pscustomobject]@{
                Params = @{ CIPPEndpoint = 'ListIntuneDeploymentStatus' }; Headers = @{}
                Query = [pscustomobject]@{ TenantFilter = 'contoso.com'; Type = $Type }; Body = [pscustomobject]@{}
            })
    }
    function New-ScriptSummary {
        param($Id, $NoIssue = 10, $Issue = 0, $Remediated = 0, $Reoccurred = 0, $DetErr = 0, $RemErr = 0, $Status = 200)
        [pscustomobject]@{ id = $Id; status = $Status; body = [pscustomobject]@{
                noIssueDetectedDeviceCount = $NoIssue; issueDetectedDeviceCount = $Issue
                issueRemediatedDeviceCount = $Remediated; issueReoccurredDeviceCount = $Reoccurred
                detectionScriptErrorDeviceCount = $DetErr; remediationScriptErrorDeviceCount = $RemErr } }
    }
    function New-PolicyOverview {
        param($Id, $Success = 5, $Err = 0, $Conflict = 0, $Pending = 0, $NA = 0, $Status = 200)
        [pscustomobject]@{ id = $Id; status = $Status; body = [pscustomobject]@{
                successCount = $Success; errorCount = $Err; conflictCount = $Conflict
                pendingCount = $Pending; notApplicableCount = $NA } }
    }
}

Describe 'Invoke-ListIntuneDeploymentStatus' {
    BeforeEach { $script:Logs = @(); $script:Parents = @(); $script:BulkResults = @() }

    Context 'validation' {
        It 'requires a tenant' {
            $r = Invoke-ListIntuneDeploymentStatus -Request ([pscustomobject]@{ Params = @{}; Headers = @{}; Query = [pscustomobject]@{}; Body = [pscustomobject]@{} })
            $r.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        }
        It 'rejects an unknown type' {
            (Invoke-Status -Type 'Widgets').StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        }
        It 'accepts FeatureUpdates' {
            $script:Parents = @()
            (Invoke-Status -Type 'FeatureUpdates').StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        }
        It 'returns an empty result set without calling the batch when there is nothing to check' {
            (Invoke-Status).Body.Metadata.Count | Should -Be 0
        }
    }

    Context 'remediation scripts' {
        It 'reports run outcomes' {
            $script:Parents = @([pscustomobject]@{ id = 's1'; displayName = 'ControlR Repair'; publisher = 'Aspendora' })
            $script:BulkResults = @(New-ScriptSummary 's1' -NoIssue 10 -Issue 3 -Remediated 2)

            $Row = (Invoke-Status).Body.Results[0]

            $Row.NoIssueDetected | Should -Be 10
            $Row.IssueDetected | Should -Be 3
            $Row.IssueRemediated | Should -Be 2
        }

        It 'a script that DETECTS issues is not unhealthy - that is it working' {
            $script:Parents = @([pscustomobject]@{ id = 's1'; displayName = 'Working' })
            $script:BulkResults = @(New-ScriptSummary 's1' -Issue 25 -Remediated 25)

            (Invoke-Status).Body.Results[0].Unhealthy | Should -BeFalse
        }

        It 'a script that ERRORS is unhealthy' {
            $script:Parents = @([pscustomobject]@{ id = 's1'; displayName = 'Broken' })
            $script:BulkResults = @(New-ScriptSummary 's1' -DetErr 2 -RemErr 1)

            $Row = (Invoke-Status).Body.Results[0]
            $Row.ScriptErrors | Should -Be 3
            $Row.Unhealthy | Should -BeTrue
        }
    }

    Context 'configuration profiles' {
        It 'reports deployment counts and flags errors or conflicts as unhealthy' {
            $script:Parents = @([pscustomobject]@{ id = 'p1'; displayName = 'Edge Policy' })
            $script:BulkResults = @(New-PolicyOverview 'p1' -Success 40 -Err 2 -Conflict 1)

            $Row = (Invoke-Status -Type 'Policies').Body.Results[0]

            $Row.Success | Should -Be 40
            $Row.Failing | Should -Be 3
            $Row.Unhealthy | Should -BeTrue
        }

        It 'notes that settings-catalog policies are not covered' {
            # Graph does not expose deviceStatusOverview on configurationPolicies; saying so beats
            # silently returning a short list.
            $script:Parents = @([pscustomobject]@{ id = 'p1'; displayName = 'Edge Policy' })
            $script:BulkResults = @(New-PolicyOverview 'p1')

            (Invoke-Status -Type 'Policies').Body.Metadata.Notes -join ' ' | Should -Match 'Settings-catalog policies'
        }
    }

    It 'reports an unreadable status as unknown, NEVER as zero' {
        # Zero would read as "deployed everywhere successfully" - the opposite of the truth.
        $script:Parents = @([pscustomobject]@{ id = 'p1'; displayName = 'Unreadable' })
        $script:BulkResults = @(New-PolicyOverview 'p1' -Status 403)

        $r = Invoke-Status -Type 'Policies'
        $Row = $r.Body.Results[0]

        $Row.StatusAvailable | Should -BeFalse
        $Row.PSObject.Properties.Name | Should -Not -Contain 'Success'
        $r.Body.Metadata.Unavailable | Should -Be 1
        $r.Body.Metadata.Notes -join ' ' | Should -Match 'unknown, not zero'
    }

    It 'sorts unhealthy items first' {
        $script:Parents = @(
            [pscustomobject]@{ id = 'a'; displayName = 'AAA Healthy' }
            [pscustomobject]@{ id = 'b'; displayName = 'ZZZ Broken' }
        )
        $script:BulkResults = @((New-PolicyOverview 'a'), (New-PolicyOverview 'b' -Err 5))

        (Invoke-Status -Type 'Policies').Body.Results[0].Name | Should -Be 'ZZZ Broken'
    }

    It 'returns an error status instead of throwing' {
        Mock New-GraphGetRequest { throw 'graph exploded' }

        (Invoke-Status).StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
        ($script:Logs -join ' ') | Should -Match 'deployment status lookup failed'
    }

    Context 'feature update profiles (B2, via the reports API)' {
        BeforeEach {
            $script:ReportThrows = $false
            $script:Parents = @([pscustomobject]@{ id = 'fu1'; displayName = 'Windows 11 25H2' })
            $script:Report = [pscustomobject]@{
                TotalRowCount = 0; LastUpdatedTime = '2026-09-18T00:00:00Z'
                Schema = @(
                    [pscustomobject]@{ Column = 'PolicyId' }, [pscustomobject]@{ Column = 'DeviceId' }
                    [pscustomobject]@{ Column = 'DeviceName' }, [pscustomobject]@{ Column = 'UPN' }
                    [pscustomobject]@{ Column = 'AlertMessage' }, [pscustomobject]@{ Column = 'AlertMessage_loc' }
                    [pscustomobject]@{ Column = 'AlertMessageDescription' }, [pscustomobject]@{ Column = 'AlertMessageDescription_loc' })
                Values = @()
            }
        }

        It 'sends the mandatory PolicyId restriction filter' {
            # Without it the service answers "One or more required filters are not set".
            $null = Invoke-Status -Type 'FeatureUpdates'
            $script:LastReportBody | Should -Match "PolicyId eq 'fu1'"
        }

        It 'reports a profile with no alerts as healthy' {
            $r = Invoke-Status -Type 'FeatureUpdates'
            $r.Body.Results[0].AlertCount | Should -Be 0
            $r.Body.Results[0].Unhealthy | Should -BeFalse
        }

        It 'maps Schema/Values rows onto named device fields' {
            # Values are positional arrays, not objects; a wrong mapping silently shifts columns.
            $script:Report.TotalRowCount = 2
            # Built as a List, not @(@(...),@(...)): PowerShell flattens nested array literals, and
            # the fixture would arrive as 16 loose cells instead of 2 rows.
            $Rows = [System.Collections.Generic.List[object]]::new()
            $Rows.Add(@('fu1', 'd1', 'LAPTOP-1', 'amber@contoso.com', 7, 'Update failed', 99, 'Disk full'))
            $Rows.Add(@('fu1', 'd2', 'LAPTOP-2', 'blair@contoso.com', 7, 'Update failed', 99, 'Disk full'))
            $script:Report.Values = $Rows

            $r = Invoke-Status -Type 'FeatureUpdates'
            $Row = $r.Body.Results[0]

            $Row.AlertCount | Should -Be 2
            $Row.DevicesAffected | Should -Be 2
            $Row.Unhealthy | Should -BeTrue
            $Row.Devices[0].DeviceName | Should -Be 'LAPTOP-1'
            $Row.Devices[0].UPN | Should -Be 'amber@contoso.com'
            # The _loc columns carry the readable text; the bare ones are numeric ids.
            $Row.Devices[0].Alert | Should -Be 'Update failed'
            $Row.Devices[0].Detail | Should -Be 'Disk full'
        }

        It 'reports an unreadable report as unknown, NEVER as zero alerts' {
            # Zero would read as "no devices are failing" - the opposite of unknown.
            $script:ReportThrows = $true

            $r = Invoke-Status -Type 'FeatureUpdates'

            $r.Body.Results[0].StatusAvailable | Should -BeFalse
            $r.Body.Results[0].PSObject.Properties.Name | Should -Not -Contain 'AlertCount'
            $r.Body.Metadata.Notes -join ' ' | Should -Match 'unknown, not zero'
        }

        It 'says so when the tenant has no feature update profiles' {
            $script:Parents = @()
            (Invoke-Status -Type 'FeatureUpdates').Body.Metadata.Notes -join ' ' | Should -Match 'No Windows Feature Update profiles'
        }
    }
}
