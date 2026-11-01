# Aspendora fork (Vikunja CIPP-22 / CIPP-24 / CIPP-27): Intune operational alerts. Graph is stubbed; Write-AlertTrace
# is stubbed to capture what each alert hands the lifecycle (rows, stable Id, state vs -Append event mode).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $Alerts = Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts'
    $Ops = Join-Path $RepoRoot 'Modules/CIPPCore/Public/IntuneOps'
    foreach ($Name in 'Test-CIPPManagedDeviceActive', 'ConvertFrom-CIPPIntuneReportTable', 'Find-CIPPDuplicateDeviceSerials', 'Format-CIPPCentralTime', 'Test-CIPPEnrollmentDiscovery') {
        . (Join-Path $Ops "$Name.ps1")
    }
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/GraphHelper/Get-AlertContentHash.ps1')
    foreach ($Name in 'IntuneStaleCheckIn', 'IntuneEnrollmentFailures', 'IntuneNewDevices', 'IntuneDuplicateDevices', 'IntuneNoCompliancePolicy', 'IntuneWindowsUpdateFailures', 'DriverUpdatesBlocked', 'EnrollmentDiscovery') {
        . (Join-Path $Alerts "Get-CIPPAlert$Name.ps1")
    }

    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid, $AsApp) }
    function New-GraphPOSTRequest { [CmdletBinding()] param($uri, $tenantid, $type, $body, $ContentType) }
    function Get-CIPPDriverBlockingPolicies { param($TenantFilter) }
    function Get-CIPPEnrollmentDiscovery { param($TenantFilter) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) }
    function Write-AlertTrace {
        param($cmdletName, $tenantFilter, $data, [switch]$Append)
        $script:Traced = @($data)
        $script:Appended = [bool]$Append
        $script:TraceCalls++
        @($data)
    }

    $script:Ago = { param([double]$Days) [datetime]::UtcNow.AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ') }
}

Describe 'Intune operational alerts' {
    BeforeEach {
        $script:Traced = $null; $script:Appended = $null; $script:TraceCalls = 0
        Mock Write-LogMessage {}
    }

    Context 'IntuneStaleCheckIn' {
        BeforeEach {
            Mock New-GraphGetRequest {
                @(
                    [pscustomobject]@{ id = 'd1'; deviceName = 'FRESH'; lastSyncDateTime = (& $script:Ago 1); managementState = 'managed' }
                    [pscustomobject]@{ id = 'd2'; deviceName = 'STALE'; lastSyncDateTime = (& $script:Ago 20); managementState = 'managed'; userPrincipalName = 'u@contoso.com' }
                    [pscustomobject]@{ id = 'd3'; deviceName = 'RETIRED'; lastSyncDateTime = (& $script:Ago 90); managementState = 'retirePending' }
                )
            }
        }

        It 'raises only active devices past the default 14 days, with a stable Id and no UserPrincipalName key' {
            Get-CIPPAlertIntuneStaleCheckIn -TenantFilter 'contoso.com' | Out-Null
            $script:Appended | Should -BeFalse
            $script:Traced.Id | Should -Be @('Stale|d2')
            $script:Traced[0].DaysSinceCheckIn | Should -Be 20
            $script:Traced[0].PSObject.Properties.Name | Should -Not -Contain 'UserPrincipalName'
        }

        It 'honours the threshold input' {
            Get-CIPPAlertIntuneStaleCheckIn -TenantFilter 'contoso.com' -InputValue @{ IntuneStaleDays = '30' } | Out-Null
            @($script:Traced).Count | Should -Be 0
            $script:TraceCalls | Should -Be 1
        }

        It 'hashes the same as days pass' {
            Get-CIPPAlertIntuneStaleCheckIn -TenantFilter 'contoso.com' | Out-Null
            $A = (Get-AlertContentHash -AlertItem $script:Traced[0]).ContentHash
            $script:Traced[0].DaysSinceCheckIn = 21
            (Get-AlertContentHash -AlertItem $script:Traced[0]).ContentHash | Should -Be $A
        }

        It 'does not reconcile when the device list cannot be read' {
            Mock New-GraphGetRequest { throw 'Forbidden' }
            Get-CIPPAlertIntuneStaleCheckIn -TenantFilter 'contoso.com' | Out-Null
            $script:TraceCalls | Should -Be 0
        }
    }

    Context 'IntuneEnrollmentFailures' {
        It 'groups retries by device, reason and day and uses event mode' {
            Mock New-GraphGetRequest {
                $Detail = @{ failureDetails = 'Blocked as personal'; remediation = 'Add a corporate identifier' }
                @(
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.enrollmentTroubleshootingEvent'; id = 'e1'; eventDateTime = '2026-10-29T04:53:10Z'; deviceId = 'dev1'; userId = 'u1'; failureReason = 'EnrollmentRestrictionDeviceCannotBeEnrolledAsPersonal'; enrollmentType = 'windowsAutoEnrollment'; troubleshootingErrorDetails = $Detail }
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.enrollmentTroubleshootingEvent'; id = 'e2'; eventDateTime = '2026-10-29T05:10:00Z'; deviceId = 'dev1'; userId = 'u1'; failureReason = 'EnrollmentRestrictionDeviceCannotBeEnrolledAsPersonal'; enrollmentType = 'windowsAutoEnrollment'; troubleshootingErrorDetails = $Detail }
                    [pscustomobject]@{ '@odata.type' = '#microsoft.graph.enrollmentTroubleshootingEvent'; id = 'e3'; eventDateTime = '2026-10-29T06:00:00Z'; deviceId = '00000000-0000-0000-0000-000000000000'; userId = 'u2'; failureReason = 'UnsupportedDeviceType'; enrollmentType = 'windowsAzureADJoin'; troubleshootingErrorDetails = @{ failureDetails = 'Not supported' } }
                )
            }
            Get-CIPPAlertIntuneEnrollmentFailures -TenantFilter 'contoso.com' | Out-Null
            $script:Appended | Should -BeTrue
            @($script:Traced).Count | Should -Be 2
            ($script:Traced | Where-Object Id -Match 'device:dev1').Attempts | Should -Be 2
            ($script:Traced | Where-Object Id -Match 'user:u2').Id | Should -Be 'EnrollFail|user:u2|UnsupportedDeviceType|2026-10-29'
        }

        It 'passes the look-back as an eventDateTime filter' {
            Mock New-GraphGetRequest { $script:Uri = $uri; @() }
            Get-CIPPAlertIntuneEnrollmentFailures -TenantFilter 'contoso.com' -InputValue @{ EnrollmentFailureLookbackHours = 6 } | Out-Null
            $script:Uri | Should -Match 'troubleshootingEvents\?\$filter=eventDateTime ge \d{4}-\d{2}-\d{2}T'
        }
    }

    Context 'IntuneNewDevices' {
        It 'announces devices enrolled inside the window once each (event mode)' {
            Mock New-GraphGetRequest {
                @(
                    [pscustomobject]@{ id = 'n1'; deviceName = 'NEW'; enrolledDateTime = (& $script:Ago 0.2); operatingSystem = 'Windows'; ownerType = 'company' }
                    [pscustomobject]@{ id = 'o1'; deviceName = 'OLD'; enrolledDateTime = (& $script:Ago 5); operatingSystem = 'Windows' }
                )
            }
            Get-CIPPAlertIntuneNewDevices -TenantFilter 'contoso.com' | Out-Null
            $script:Appended | Should -BeTrue
            $script:Traced.Id | Should -Be @('NewDevice|n1')
        }
    }

    Context 'IntuneDuplicateDevices' {
        It 'raises a serial with a keep / clean-up recommendation and never deletes' {
            Mock New-GraphGetRequest {
                @(
                    [pscustomobject]@{ id = 'a'; deviceName = 'PC-OLD'; serialNumber = 'SN1'; lastSyncDateTime = '2026-01-01T00:00:00Z'; managementState = 'managed' }
                    [pscustomobject]@{ id = 'b'; deviceName = 'PC-NEW'; serialNumber = 'SN1'; lastSyncDateTime = '2026-10-30T00:00:00Z'; managementState = 'managed' }
                )
            }
            Mock New-GraphPOSTRequest {}
            Get-CIPPAlertIntuneDuplicateDevices -TenantFilter 'contoso.com' | Out-Null
            $script:Traced.Id | Should -Be @('DupSerial|SN1')
            $script:Traced[0].Keep | Should -Match '^PC-NEW'
            $script:Traced[0].Message | Should -Match 'not applied'
            Should -Invoke New-GraphPOSTRequest -Times 0
        }
    }

    Context 'IntuneNoCompliancePolicy' {
        BeforeEach {
            Mock New-GraphGetRequest {
                if ($uri -match 'deviceComplianceSettingStates') {
                    @(
                        [pscustomobject]@{ deviceId = 'x1'; state = 'nonCompliant' }
                        [pscustomobject]@{ deviceId = 'x2'; state = 'error' }
                        [pscustomobject]@{ deviceId = 'x3'; state = 'compliant' }
                        [pscustomobject]@{ deviceId = 'x4'; state = 'nonCompliant' }
                        [pscustomobject]@{ deviceId = 'gone'; state = 'nonCompliant' }
                        # User-assigned policy: the system row (no user) is nonCompliant, the signed-in user's row compliant.
                        [pscustomobject]@{ deviceId = 'x5'; state = 'nonCompliant' }
                        [pscustomobject]@{ deviceId = 'x5'; state = 'compliant'; userPrincipalName = 'ian@contoso.com' }
                        # Two rows, neither compliant: still uncovered.
                        [pscustomobject]@{ deviceId = 'x6'; state = 'nonCompliant' }
                        [pscustomobject]@{ deviceId = 'x6'; state = 'nonCompliant'; userPrincipalName = 'kiosk@contoso.com' }
                    )
                } else {
                    @(
                        [pscustomobject]@{ id = 'x1'; deviceName = 'NOPOL'; operatingSystem = 'Windows'; enrolledDateTime = (& $script:Ago 30); managementState = 'managed' }
                        [pscustomobject]@{ id = 'x2'; deviceName = 'ERR'; operatingSystem = 'Windows'; enrolledDateTime = (& $script:Ago 30); managementState = 'managed' }
                        [pscustomobject]@{ id = 'x3'; deviceName = 'OK'; operatingSystem = 'Windows'; enrolledDateTime = (& $script:Ago 30); managementState = 'managed' }
                        [pscustomobject]@{ id = 'x4'; deviceName = 'BRANDNEW'; operatingSystem = 'iOS'; enrolledDateTime = (& $script:Ago 0.1); managementState = 'managed' }
                        [pscustomobject]@{ id = 'x5'; deviceName = 'USERPOLICY'; operatingSystem = 'Windows'; enrolledDateTime = (& $script:Ago 30); managementState = 'managed' }
                        [pscustomobject]@{ id = 'x6'; deviceName = 'KIOSK'; operatingSystem = 'Windows'; enrolledDateTime = (& $script:Ago 30); managementState = 'managed' }
                    )
                }
            }
        }

        It 'raises devices with no policy, skipping new, vanished and evaluation-error devices by default' {
            Get-CIPPAlertIntuneNoCompliancePolicy -TenantFilter 'contoso.com' | Out-Null
            $script:Traced.Id | Should -Be @('NoCompliance|x1', 'NoCompliance|x6')
        }

        It 'does not raise a device whose signed-in user is covered by a user-assigned policy (system row nonCompliant)' {
            Get-CIPPAlertIntuneNoCompliancePolicy -TenantFilter 'contoso.com' | Out-Null
            $script:Traced.Id | Should -Not -Contain 'NoCompliance|x5'
        }

        It 'adds evaluation errors when asked' {
            Get-CIPPAlertIntuneNoCompliancePolicy -TenantFilter 'contoso.com' -InputValue @{ NoComplianceIncludeErrors = $true } | Out-Null
            @($script:Traced.Id | Sort-Object) | Should -Be @('NoCompliance|x1', 'NoCompliance|x2', 'NoCompliance|x6')
        }

        It 'does not treat the string false as on' {
            Get-CIPPAlertIntuneNoCompliancePolicy -TenantFilter 'contoso.com' -InputValue @{ NoComplianceIncludeErrors = 'false' } | Out-Null
            $script:Traced.Id | Should -Be @('NoCompliance|x1', 'NoCompliance|x6')
        }
    }

    Context 'IntuneWindowsUpdateFailures' {
        It 'reads the feature update report per profile and keys rows on profile, device and alert' {
            Mock New-GraphGetRequest { @([pscustomobject]@{ id = 'fu1'; displayName = 'Win 11 25H2' }) }
            Mock New-GraphPOSTRequest {
                $script:Posted = @{ Uri = $uri; Body = $body }
                [pscustomobject]@{ Schema = @(@{ Column = 'DeviceName' }, @{ Column = 'UPN' }, @{ Column = 'AlertMessage' }, @{ Column = 'AlertMessage_loc' }); Values = @(, @('PC1', 'u@contoso.com', '1001', 'Install failed')) }
            }
            Get-CIPPAlertIntuneWindowsUpdateFailures -TenantFilter 'contoso.com' | Out-Null
            $script:Posted.Uri | Should -Match 'getWindowsUpdateAlertsPerPolicyPerDeviceReport$'
            $script:Posted.Body | Should -Match "PolicyId eq 'fu1'"
            $script:Traced.Id | Should -Be @('WU|FeatureUpdate|fu1|PC1|1001')
            $script:Traced[0].Alert | Should -Be 'Install failed'
        }

        It 'does not reconcile when a report fails' {
            Mock New-GraphGetRequest { @([pscustomobject]@{ id = 'fu1'; displayName = 'P' }) }
            Mock New-GraphPOSTRequest { throw 'BadRequest' }
            Get-CIPPAlertIntuneWindowsUpdateFailures -TenantFilter 'contoso.com' | Out-Null
            $script:TraceCalls | Should -Be 0
        }

        It 'only reads quality and driver reports when switched on' {
            Mock New-GraphGetRequest { $script:Lists += @($uri); @() }
            $script:Lists = @()
            Get-CIPPAlertIntuneWindowsUpdateFailures -TenantFilter 'contoso.com' | Out-Null
            ($script:Lists -join ' ') | Should -Not -Match 'windowsQualityUpdateProfiles|windowsDriverUpdateProfiles'
            $script:Lists = @()
            Get-CIPPAlertIntuneWindowsUpdateFailures -TenantFilter 'contoso.com' -InputValue @{ WUFailuresIncludeQuality = $true; WUFailuresIncludeDrivers = 'true' } | Out-Null
            ($script:Lists -join ' ') | Should -Match 'windowsQualityUpdateProfiles'
            ($script:Lists -join ' ') | Should -Match 'windowsDriverUpdateProfiles'
        }
    }

    Context 'DriverUpdatesBlocked' {
        BeforeEach {
            Mock Get-CIPPDriverBlockingPolicies {
                [pscustomobject]@{
                    Findings = @(
                        [pscustomobject]@{ Id = 'Ring|r1'; Kind = 'UpdateRing'; PolicyName = 'Ring'; Assigned = $true; AssignmentCount = 1; Message = 'blocks' }
                        [pscustomobject]@{ Id = 'Catalog|c1'; Kind = 'SettingsCatalog'; PolicyName = 'Cat'; Assigned = $false; AssignmentCount = 0; Message = 'blocks' }
                    )
                    Errors   = @()
                }
            }
        }

        It 'raises assigned blockers only by default' {
            Get-CIPPAlertDriverUpdatesBlocked -TenantFilter 'contoso.com' | Out-Null
            $script:Traced.Id | Should -Be @('Ring|r1')
        }

        It 'includes unassigned blockers when asked' {
            Get-CIPPAlertDriverUpdatesBlocked -TenantFilter 'contoso.com' -InputValue @{ DriverBlockIncludeUnassigned = $true } | Out-Null
            @($script:Traced).Count | Should -Be 2
        }

        It 'skips reporting when a policy family could not be read' {
            Mock Get-CIPPDriverBlockingPolicies { [pscustomobject]@{ Findings = @(); Errors = @('Update rings: Forbidden') } }
            Get-CIPPAlertDriverUpdatesBlocked -TenantFilter 'contoso.com' | Out-Null
            $script:TraceCalls | Should -Be 0
        }
    }

    Context 'EnrollmentDiscovery' {
        It 'raises Warning findings in state mode' {
            Mock Get-CIPPEnrollmentDiscovery {
                [pscustomobject]@{
                    MdmScope = 'none'; Domains = @([pscustomobject]@{ Domain = 'contoso.com'; LookupError = $false }); Errors = @()
                    Findings = @(
                        [pscustomobject]@{ Id = 'CnameWithScopeNone'; Category = 'CnameWithScopeNone'; Severity = 'Warning'; Domain = ''; Message = 'm' }
                        [pscustomobject]@{ Id = 'CnameLegacyTarget|contoso.com'; Category = 'CnameLegacyTarget'; Severity = 'Info'; Domain = 'contoso.com'; Message = 'm' }
                    )
                }
            }
            Get-CIPPAlertEnrollmentDiscovery -TenantFilter 'contoso.com' | Out-Null
            $script:Appended | Should -BeFalse
            $script:Traced.Id | Should -Be @('CnameWithScopeNone')
        }

        It 'does not reconcile when the MDM scope could not be read' {
            Mock Get-CIPPEnrollmentDiscovery { [pscustomobject]@{ MdmScope = 'unknown'; Domains = @(); Findings = @(); Errors = @('MDM user scope: Forbidden') } }
            Get-CIPPAlertEnrollmentDiscovery -TenantFilter 'contoso.com' | Out-Null
            $script:TraceCalls | Should -Be 0
        }

        It 'switches to append mode when a DNS lookup failed' {
            Mock Get-CIPPEnrollmentDiscovery {
                [pscustomobject]@{ MdmScope = 'all'; Domains = @([pscustomobject]@{ Domain = 'contoso.com'; LookupError = $true }); Errors = @('DNS lookup for contoso.com: timeout'); Findings = @() }
            }
            Get-CIPPAlertEnrollmentDiscovery -TenantFilter 'contoso.com' | Out-Null
            $script:Appended | Should -BeTrue
        }
    }
}
