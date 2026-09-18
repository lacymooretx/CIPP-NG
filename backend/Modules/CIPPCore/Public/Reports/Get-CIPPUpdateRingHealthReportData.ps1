function Get-CIPPUpdateRingHealthReportData {
    <#
    .SYNOPSIS
        Gather the Windows Update Ring Health Report model for a single tenant.
    .DESCRIPTION
        Audits Windows Update for Business rings for configurations that silently stop devices
        patching. The valuable rules are the CROSS-POLICY ones - a deferral or driver exclusion on a
        ring can neutralise a Feature Update or Driver Update profile that looks perfectly healthy on
        its own page, so neither view alone shows the problem.

        AUTOPATCH-MANAGED RINGS ARE LISTED BUT NOT FLAGGED. Microsoft owns the
        "Windows Autopatch Update Policy - *" rings and sets values that would otherwise trip these
        rules by design (the Autopatch "Last" ring legitimately defers quality updates by 11 days).
        Raising findings we cannot act on would make this report noise on every Autopatch tenant, so
        they are reported as managed and excluded from the findings.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    # Above this, quality updates are deferred long enough that a device can miss a full patch cycle.
    $MaxQualityDeferralDays = 7
    $GraphBeta = 'https://graph.microsoft.com/beta'

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Sections = [System.Collections.Generic.List[object]]::new()

    function Add-Finding($Title, $Status, $Detail) { $Findings.Add(@{ Title = $Title; Status = $Status; Detail = $Detail }) }
    function Add-Section($Title, $Status, $Description, $Columns, $Rows, $Empty) {
        $Sections.Add(@{ Title = $Title; Status = $Status; Description = $Description; Columns = $Columns; Rows = $Rows; Empty = $Empty })
    }
    function New-RowList { , [System.Collections.Generic.List[object]]::new() }
    function Invoke-Section($Name, [scriptblock]$Builder) {
        try { & $Builder } catch {
            $r = New-RowList; $r.Add(@("$($_.Exception.Message)"))
            Add-Section $Name 'warn' 'This section could not be retrieved.' @('Error') $r 'Data unavailable.'
        }
    }

    $Org = $null
    try { $Org = New-GraphGetRequest -uri "$GraphBeta/organization" -tenantid $TenantFilter | Select-Object -First 1 } catch {}
    $TenantName = if ($Org.displayName) { $Org.displayName } else { $TenantFilter }
    $DefaultDomain = ($Org.verifiedDomains | Where-Object { $_.isDefault }).name
    if (-not $DefaultDomain) { $DefaultDomain = $TenantFilter }

    # Cross-policy context. A ring's deferral or driver exclusion only MATTERS if a profile of the
    # corresponding type actually exists, so these are gathered before the rules run.
    $FeatureProfiles = @()
    $DriverProfiles = @()
    try { $FeatureProfiles = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/windowsFeatureUpdateProfiles?`$select=id,displayName" -tenantid $TenantFilter) } catch {}
    try { $DriverProfiles = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/windowsDriverUpdateProfiles?`$select=id,displayName" -tenantid $TenantFilter) } catch {}

    $Rings = @()
    try {
        $Rings = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=assignments" -tenantid $TenantFilter)
    } catch {
        Add-Section 'Update Rings' 'warn' 'Update rings could not be retrieved.' @('Error') (New-RowList) 'Data unavailable.'
    }

    $Issues = [System.Collections.Generic.List[object]]::new()
    function Add-Issue($Ring, $Severity, $Rule, $Detail) {
        $Issues.Add([pscustomobject]@{ Ring = $Ring; Severity = $Severity; Rule = $Rule; Detail = $Detail })
    }

    Invoke-Section 'Update Rings' {
        $r = New-RowList
        $ManagedCount = 0

        foreach ($Ring in ($Rings | Sort-Object displayName)) {
            $Name = [string]$Ring.displayName
            $IsAutopatch = $Name -like 'Windows Autopatch Update Policy*'
            if ($IsAutopatch) { $ManagedCount++ }

            $Assignments = @($Ring.assignments)
            $TargetsAllDevices = @($Assignments | Where-Object { $_.target.'@odata.type' -match 'allDevicesAssignmentTarget' }).Count -gt 0
            $HasExclusions = @($Assignments | Where-Object { $_.target.'@odata.type' -match 'exclusionGroupAssignmentTarget' }).Count -gt 0

            $r.Add(@(
                    $Name
                    $(if ($IsAutopatch) { 'Autopatch-managed' } else { 'Manual' })
                    $(if ($Ring.qualityUpdatesPaused) { 'PAUSED' } else { "$([int]$Ring.qualityUpdatesDeferralPeriodInDays)d" })
                    $(if ($Ring.featureUpdatesPaused) { 'PAUSED' } else { "$([int]$Ring.featureUpdatesDeferralPeriodInDays)d" })
                    $(if ($null -ne $Ring.deadlineForQualityUpdatesInDays) { "$([int]$Ring.deadlineForQualityUpdatesInDays)d" } else { 'none' })
                    $(if ($null -ne $Ring.deadlineGracePeriodInDays) { "$([int]$Ring.deadlineGracePeriodInDays)d" } else { 'none' })
                    $(if ($Ring.driversExcluded) { 'excluded' } else { 'included' })
                    [string]$Assignments.Count
                ))

            # Microsoft owns these values; a finding we cannot act on is noise.
            if ($IsAutopatch) { continue }

            if ($Ring.qualityUpdatesPaused) {
                Add-Issue $Name 'Critical' 'Quality updates paused' 'Devices in this ring are receiving no security patches.'
            }
            if ($Ring.featureUpdatesPaused) {
                Add-Issue $Name 'Medium' 'Feature updates paused' 'Feature updates are held; confirm this is deliberate and time-boxed.'
            }
            if ([int]$Ring.featureUpdatesDeferralPeriodInDays -gt 0 -and $FeatureProfiles.Count -gt 0) {
                Add-Issue $Name 'High' 'Feature deferral blocks a Feature Update profile' "Deferral of $([int]$Ring.featureUpdatesDeferralPeriodInDays) days applies while $($FeatureProfiles.Count) Feature Update profile(s) exist; the deferral wins and the profile never lands."
            }
            if ($Ring.driversExcluded -and $DriverProfiles.Count -gt 0) {
                Add-Issue $Name 'High' 'Drivers excluded while Driver Update profiles exist' "Drivers are excluded on this ring while $($DriverProfiles.Count) Driver Update profile(s) exist; those profiles never apply."
            }
            if ($null -eq $Ring.deadlineForQualityUpdatesInDays -and -not $Ring.qualityUpdatesPaused) {
                Add-Issue $Name 'High' 'No quality update deadline' 'Without a deadline a device can postpone a security update indefinitely.'
            }
            if ([int]$Ring.qualityUpdatesDeferralPeriodInDays -gt $MaxQualityDeferralDays) {
                Add-Issue $Name 'High' 'Quality deferral exceeds recommended maximum' "Deferred $([int]$Ring.qualityUpdatesDeferralPeriodInDays) days, above the $MaxQualityDeferralDays-day maximum; a device can miss a full patch cycle."
            }
            if ($Assignments.Count -eq 0) {
                Add-Issue $Name 'Medium' 'Ring has no assignments' 'This ring applies to nothing. Either it is abandoned, or devices assumed to be covered are not.'
            }
            if ($TargetsAllDevices -and -not $HasExclusions) {
                Add-Issue $Name 'Medium' 'Targets All Devices with no exclusions' 'A bad update reaches every device at once; there is no ring to catch it first.'
            }
            if ($null -ne $Ring.deadlineGracePeriodInDays -and [int]$Ring.deadlineGracePeriodInDays -eq 0) {
                Add-Issue $Name 'Medium' 'Zero grace period' 'Devices reboot immediately at the deadline with no grace window.'
            }
            if ($Ring.deliveryOptimizationMode -eq 'httpOnly') {
                Add-Issue $Name 'Low' 'Delivery Optimization is HTTP-only' 'No peer-to-peer sharing; every device pulls the full payload over the WAN.'
            }
            if ($null -eq $Ring.deadlineForFeatureUpdatesInDays -and -not $Ring.featureUpdatesPaused) {
                Add-Issue $Name 'Low' 'No feature update deadline' 'Feature updates have no enforced install-by date.'
            }
        }

        $Columns = @('Ring', 'Managed By', 'Quality', 'Feature', 'Quality Deadline', 'Grace', 'Drivers', 'Assignments')
        if ($Rings.Count -eq 0) {
            # States the observation and stops. An earlier version concluded "update behaviour is
            # unmanaged", which is an inference this report cannot support: it sees Intune through
            # Graph and has no visibility of third-party patch managers. Most of this estate is
            # patched by Action1, where having no WUfB rings is the intended architecture rather
            # than a gap - so the old wording reported healthy tenants as a patching failure.
            Add-Section 'Update Rings' 'warn' 'No Windows Update for Business rings are configured.' $Columns (New-RowList) 'No Windows Update for Business rings found. If patching is handled by another tool (for example Action1), this is expected.'
            Add-Finding 'No Windows Update for Business rings' 'warn' 'This tenant has no WUfB rings. Confirm patching is handled elsewhere - this report only sees Intune, so it cannot tell an intentional third-party patching setup from an actual gap.'
        } else {
            Add-Section 'Update Rings' 'pass' "$($Rings.Count) ring(s); $ManagedCount managed by Windows Autopatch and excluded from the findings below." $Columns $r $null
        }
    }

    Invoke-Section 'Findings' {
        $Order = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
        $r = New-RowList
        foreach ($Issue in ($Issues | Sort-Object { $Order[$_.Severity] }, Ring)) {
            $r.Add(@($Issue.Severity, $Issue.Ring, $Issue.Rule, $Issue.Detail))
        }

        $Critical = @($Issues | Where-Object { $_.Severity -eq 'Critical' }).Count
        $High = @($Issues | Where-Object { $_.Severity -eq 'High' }).Count
        $Status = if ($Critical -gt 0) { 'fail' } elseif ($High -gt 0) { 'warn' } elseif ($Issues.Count -gt 0) { 'warn' } else { 'pass' }

        Add-Section 'Findings' $Status 'Configurations that stop or delay devices patching. Autopatch-managed rings are excluded.' @('Severity', 'Ring', 'Rule', 'Detail') $r 'No update ring issues found.'

        if ($Critical -gt 0) { Add-Finding 'Devices are not receiving security patches' 'fail' "$Critical ring(s) have quality updates paused." }
        if ($High -gt 0) { Add-Finding 'Update delivery is compromised' 'warn' "$High high-severity issue(s), including deferrals or exclusions that neutralise update profiles." }
        if ($Issues.Count -eq 0 -and $Rings.Count -gt 0) { Add-Finding 'Update rings are healthy' 'pass' 'No issues found in the manually managed update rings.' }
    }

    return @{
        Title         = 'Windows Update Ring Health Report'
        TenantName    = $TenantName
        TenantDomain  = $DefaultDomain
        GeneratedDate = (Get-Date).ToString('dd MMMM yyyy')
        Findings      = $Findings
        Sections      = $Sections
    }
}
