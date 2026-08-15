function Get-CIPPIntuneConfigReportData {
    <#
    .SYNOPSIS
        Gather the Intune Configuration Document model for a single tenant.
    .DESCRIPTION
        Assembles a full, readable snapshot of a tenant's Intune configuration - the
        "how is this client set up" document we have never had written down anywhere.

        Reads from the CIPP reporting cache (Get-CIPPIntune*Report) rather than calling
        Graph per section, so a nightly run across every tenant costs almost nothing.
        Returns the standard report model consumed by Write-CippReportHtml, and by
        ConvertTo-ITGlueSectionHtml for the IT Glue flexible asset.

        Every section is gathered defensively: a failure in one section is recorded as a
        collection note and the rest of the document still renders. A section that could
        not be read must never look like a tenant with nothing configured.

        Each section carries a stable 'Key' used to map it onto an IT Glue trait.
    .PARAMETER TenantFilter
        Tenant default domain name.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    $GraphBeta = 'https://graph.microsoft.com/beta'
    $Findings = [System.Collections.Generic.List[object]]::new()
    $Sections = [System.Collections.Generic.List[object]]::new()
    $Notes = [System.Collections.Generic.List[object]]::new()

    function Add-Finding($Title, $Status, $Detail) {
        $Findings.Add(@{ Title = $Title; Status = $Status; Detail = $Detail })
    }
    function Add-Section($Key, $Title, $Status, $Description, $Columns, $Rows, $Empty) {
        $Sections.Add(@{ Key = $Key; Title = $Title; Status = $Status; Description = $Description; Columns = $Columns; Rows = $Rows; Empty = $Empty })
    }
    function New-RowList { , [System.Collections.Generic.List[object]]::new() }
    # Run a section builder defensively. A failed section is recorded in the collection
    # notes with its reason - never silently rendered as "nothing configured".
    function Invoke-Section($Key, $Name, [scriptblock]$Builder) {
        try { & $Builder } catch {
            $Reason = $_.Exception.Message
            $Notes.Add(@{ Section = $Name; Detail = $Reason })
            $r = New-RowList; $r.Add(@($Reason))
            Add-Section $Key $Name 'warn' 'This section could not be retrieved - the data below is incomplete.' @('Error') $r 'Data unavailable.'
        }
    }

    # ---- tenant identity -----------------------------------------------------------
    $Org = $null
    try { $Org = New-GraphGetRequest -uri "$GraphBeta/organization" -tenantid $TenantFilter | Select-Object -First 1 } catch {}
    $TenantName = if ($Org.displayName) { $Org.displayName } else { $TenantFilter }
    $DefaultDomain = ($Org.verifiedDomains | Where-Object { $_.isDefault }).name
    if (-not $DefaultDomain) { $DefaultDomain = $TenantFilter }

    # ---- shared source data --------------------------------------------------------
    $Policies = @()
    try { $Policies = @(Get-CIPPIntunePolicyReport -TenantFilter $TenantFilter) } catch {
        $Notes.Add(@{ Section = 'Policies'; Detail = "Policy cache unavailable: $($_.Exception.Message)" })
    }

    function Select-Family([string[]]$Names) {
        @($Policies | Where-Object { $_.URLName -and ($Names -contains $_.URLName) })
    }
    function Get-Assigned($Policy) {
        if ($Policy.PolicyAssignment) { return [string]$Policy.PolicyAssignment }
        if ($Policy.isAssigned -eq $false) { return 'Not assigned' }
        if ($Policy.assignments) { return "$(@($Policy.assignments).Count) assignment(s)" }
        return 'Not assigned'
    }
    function Get-Modified($Policy) {
        if ($Policy.lastModifiedDateTime) {
            try { return ([datetime]$Policy.lastModifiedDateTime).ToString('yyyy-MM-dd') } catch { return '' }
        }
        return ''
    }

    # Mutable through the section closures - a plain [int] would be copied into the
    # child scope, and $script: would leak across tenants in a nightly all-tenant run.
    $State = @{ Count = 0 }

    # ---- Configuration Profiles ----------------------------------------------------
    Invoke-Section 'ConfigurationProfiles' 'Configuration Profiles' {
        $Items = Select-Family @('DeviceConfigurations', 'GroupPolicyConfigurations')
        $r = New-RowList
        foreach ($p in $Items) {
            $Kind = if ($p.URLName -eq 'GroupPolicyConfigurations') { 'Administrative Template (ADMX)' } else { 'Device Configuration' }
            $Name = if ($p.displayName) { $p.displayName } else { $p.name }
            $r.Add(@($Name, $Kind, [string]$p.description, (Get-Assigned $p), (Get-Modified $p)))
        }
        $State.Count += $Items.Count
        Add-Section 'ConfigurationProfiles' 'Configuration Profiles' 'info' `
            "$($Items.Count) device configuration profiles and administrative templates." `
            @('Profile', 'Type', 'Description', 'Assigned To', 'Modified') $r `
            'No device configuration profiles are configured in this tenant.'
    }

    # ---- Settings Catalog ----------------------------------------------------------
    # One row per configured setting. This is the section that makes the document
    # actually useful, and the one that pushes hardest against IT Glue's 64KB field cap.
    Invoke-Section 'SettingsCatalog' 'Settings Catalog' {
        $Items = Select-Family @('ConfigurationPolicies')
        $r = New-RowList
        foreach ($p in $Items) {
            $Name = if ($p.name) { $p.name } else { $p.displayName }
            $Assigned = Get-Assigned $p
            $Platform = if ($p.platforms) { [string]$p.platforms } else { '' }
            $SettingRows = [System.Collections.Generic.List[object]]::new()
            foreach ($s in @($p.settings)) {
                foreach ($Flat in (ConvertFrom-CIPPIntuneSettingInstance -Instance $s)) { $SettingRows.Add($Flat) }
            }
            if ($SettingRows.Count -eq 0) {
                $r.Add(@($Name, $Platform, '(no settings returned)', '', $Assigned))
            } else {
                foreach ($Flat in $SettingRows) {
                    $r.Add(@($Name, $Platform, $Flat.Setting, $Flat.Value, $Assigned))
                }
            }
        }
        $State.Count += $Items.Count
        Add-Section 'SettingsCatalog' 'Settings Catalog' 'info' `
            "$($Items.Count) settings catalog policies, $($r.Count) configured settings." `
            @('Policy', 'Platform', 'Setting', 'Value', 'Assigned To') $r `
            'No settings catalog policies are configured in this tenant.'
    }

    # ---- Compliance Policies -------------------------------------------------------
    Invoke-Section 'CompliancePolicies' 'Compliance Policies' {
        $Items = Select-Family @('deviceCompliancePolicies')
        if (-not $Items) {
            try { $Items = @(Get-CIPPIntuneCompliancePolicyReport -TenantFilter $TenantFilter) } catch {}
        }
        $r = New-RowList
        foreach ($p in $Items) {
            $Platform = if ($p.PolicyTypeName) { $p.PolicyTypeName }
            elseif ($p.'@odata.type') { ($p.'@odata.type' -replace '#microsoft\.graph\.', '') }
            else { '' }
            $Name = if ($p.displayName) { $p.displayName } else { $p.name }
            $r.Add(@($Name, $Platform, [string]$p.description, (Get-Assigned $p), (Get-Modified $p)))
        }
        $State.Count += @($Items).Count
        Add-Section 'CompliancePolicies' 'Compliance Policies' 'info' `
            "$(@($Items).Count) device compliance policies." `
            @('Policy', 'Platform', 'Description', 'Assigned To', 'Modified') $r `
            'No compliance policies are configured. Devices cannot be evaluated for compliance.'
    }

    # ---- Security Baselines and App Protection -------------------------------------
    Invoke-Section 'SecurityBaselines' 'Security Baselines and App Protection' {
        $Baselines = Select-Family @('Intents')
        $Protection = @()
        try { $Protection = @(Get-CIPPIntuneAppProtectionPolicyReport -TenantFilter $TenantFilter) } catch {
            $Notes.Add(@{ Section = 'Security Baselines and App Protection'; Detail = "App protection policies unavailable: $($_.Exception.Message)" })
        }
        $r = New-RowList
        foreach ($p in $Baselines) {
            $Name = if ($p.displayName) { $p.displayName } else { $p.name }
            $r.Add(@('Security Baseline', $Name, [string]$p.description, (Get-Assigned $p)))
        }
        foreach ($p in $Protection) {
            $Name = if ($p.displayName) { $p.displayName } else { $p.name }
            $Kind = if ($p.'@odata.type') { ($p.'@odata.type' -replace '#microsoft\.graph\.', '') } else { 'App Protection' }
            $r.Add(@($Kind, $Name, [string]$p.description, (Get-Assigned $p)))
        }
        $State.Count += (@($Baselines).Count + @($Protection).Count)
        Add-Section 'SecurityBaselines' 'Security Baselines and App Protection' 'info' `
            "$(@($Baselines).Count) security baselines, $(@($Protection).Count) app protection policies." `
            @('Type', 'Name', 'Description', 'Assigned To') $r `
            'No security baselines or app protection policies are configured.'
    }

    # ---- Update Rings --------------------------------------------------------------
    Invoke-Section 'UpdateRings' 'Update Rings' {
        $Items = Select-Family @('WindowsDriverUpdateProfiles', 'WindowsFeatureUpdateProfiles', 'windowsQualityUpdatePolicies', 'windowsQualityUpdateProfiles')
        $Rings = @($Policies | Where-Object {
                $_.URLName -eq 'DeviceConfigurations' -and $_.'@odata.type' -match 'windowsUpdateForBusinessConfiguration'
            })
        $r = New-RowList
        foreach ($p in $Rings) {
            $Name = if ($p.displayName) { $p.displayName } else { $p.name }
            $Detail = @(
                if ($null -ne $p.qualityUpdatesDeferralPeriodInDays) { "Quality deferral $($p.qualityUpdatesDeferralPeriodInDays)d" }
                if ($null -ne $p.featureUpdatesDeferralPeriodInDays) { "Feature deferral $($p.featureUpdatesDeferralPeriodInDays)d" }
                if ($p.automaticUpdateMode) { "Mode $($p.automaticUpdateMode)" }
            ) -join '; '
            $r.Add(@('Update Ring', $Name, $Detail, (Get-Assigned $p)))
        }
        foreach ($p in $Items) {
            $Kind = switch ($p.URLName) {
                'WindowsDriverUpdateProfiles' { 'Driver Update Profile' }
                'WindowsFeatureUpdateProfiles' { 'Feature Update Profile' }
                default { 'Quality Update Policy' }
            }
            $Name = if ($p.displayName) { $p.displayName } else { $p.name }
            $Detail = @(
                if ($p.featureUpdateVersion) { "Target $($p.featureUpdateVersion)" }
                if ($p.approvalType) { "Approval $($p.approvalType)" }
                if ($p.deployableContentDisplayName) { [string]$p.deployableContentDisplayName }
            ) -join '; '
            $r.Add(@($Kind, $Name, $Detail, (Get-Assigned $p)))
        }
        $State.Count += (@($Items).Count + @($Rings).Count)
        Add-Section 'UpdateRings' 'Update Rings' 'info' `
            "$(@($Rings).Count) update rings, $(@($Items).Count) feature/quality/driver update profiles." `
            @('Type', 'Name', 'Configuration', 'Assigned To') $r `
            'No Windows Update policies are configured. Devices update on Microsoft defaults.'
    }

    # ---- Apps and Scripts ----------------------------------------------------------
    Invoke-Section 'AppsAndScripts' 'Apps and Scripts' {
        $Apps = @()
        try { $Apps = @(Get-CIPPIntuneApplicationReport -TenantFilter $TenantFilter) } catch {
            $Notes.Add(@{ Section = 'Apps and Scripts'; Detail = "Applications unavailable: $($_.Exception.Message)" })
        }
        $Scripts = @()
        try { $Scripts = @(Get-CIPPIntuneScriptReport -TenantFilter $TenantFilter) } catch {
            $Notes.Add(@{ Section = 'Apps and Scripts'; Detail = "Scripts unavailable: $($_.Exception.Message)" })
        }
        $r = New-RowList
        foreach ($a in $Apps) {
            $Kind = if ($a.'@odata.type') { ($a.'@odata.type' -replace '#microsoft\.graph\.', '') } else { 'Application' }
            $Name = if ($a.displayName) { $a.displayName } else { $a.name }
            $r.Add(@('Application', $Name, $Kind, [string]$a.publisher, (Get-Assigned $a)))
        }
        foreach ($s in $Scripts) {
            $Kind = if ($s.ScriptType) { [string]$s.ScriptType }
            elseif ($s.'@odata.type') { ($s.'@odata.type' -replace '#microsoft\.graph\.', '') }
            else { 'Script' }
            $Name = if ($s.displayName) { $s.displayName } else { $s.name }
            # Script bodies are deliberately not documented - they frequently carry secrets.
            $r.Add(@('Script', $Name, $Kind, [string]$s.description, (Get-Assigned $s)))
        }
        $State.Count += (@($Apps).Count + @($Scripts).Count)
        Add-Section 'AppsAndScripts' 'Apps and Scripts' 'info' `
            "$(@($Apps).Count) applications, $(@($Scripts).Count) scripts and remediations. Script contents are intentionally excluded." `
            @('Type', 'Name', 'Kind', 'Detail', 'Assigned To') $r `
            'No applications or scripts are deployed from Intune.'
    }

    # ---- Enrollment and Autopilot --------------------------------------------------
    Invoke-Section 'Enrollment' 'Enrollment and Autopilot' {
        $r = New-RowList
        $Autopilot = @()
        try {
            $Autopilot = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/windowsAutopilotDeploymentProfiles" -tenantid $TenantFilter)
        } catch {
            $Notes.Add(@{ Section = 'Enrollment and Autopilot'; Detail = "Autopilot deployment profiles unavailable: $($_.Exception.Message)" })
        }
        $EnrollmentConfigs = @()
        try {
            $EnrollmentConfigs = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/deviceEnrollmentConfigurations" -tenantid $TenantFilter)
        } catch {
            $Notes.Add(@{ Section = 'Enrollment and Autopilot'; Detail = "Enrollment configurations unavailable: $($_.Exception.Message)" })
        }

        foreach ($p in $Autopilot) {
            $Detail = @(
                if ($p.deviceNameTemplate) { "Name template $($p.deviceNameTemplate)" }
                if ($null -ne $p.extractHardwareHash) { "Hardware hash $($p.extractHardwareHash)" }
                if ($p.outOfBoxExperienceSetting.deviceUsageType) { "Usage $($p.outOfBoxExperienceSetting.deviceUsageType)" }
            ) -join '; '
            $r.Add(@('Autopilot Profile', [string]$p.displayName, $Detail, [string]$p.description))
        }
        foreach ($p in $EnrollmentConfigs) {
            $Kind = if ($p.'@odata.type') { ($p.'@odata.type' -replace '#microsoft\.graph\.', '' -replace 'deviceEnrollment', '') } else { 'Enrollment Configuration' }
            $r.Add(@($Kind, [string]$p.displayName, "Priority $($p.priority)", [string]$p.description))
        }
        $State.Count += (@($Autopilot).Count + @($EnrollmentConfigs).Count)
        Add-Section 'Enrollment' 'Enrollment and Autopilot' 'info' `
            "$(@($Autopilot).Count) Autopilot deployment profiles, $(@($EnrollmentConfigs).Count) enrollment configurations." `
            @('Type', 'Name', 'Configuration', 'Description') $r `
            'No Autopilot profiles or custom enrollment configurations are present.'
    }

    # ---- RBAC and Scope Tags -------------------------------------------------------
    # Scope tags silently change which admins see and manage a policy, and delegated Intune
    # admins are invisible in every other view we have. Neither is in the policy cache, so
    # these are read live - cheaply, three list calls.
    Invoke-Section 'RBAC' 'RBAC and Scope Tags' {
        $r = New-RowList

        $ScopeTags = @()
        try { $ScopeTags = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/roleScopeTags" -tenantid $TenantFilter) } catch {
            $Notes.Add(@{ Section = 'RBAC and Scope Tags'; Detail = "Scope tags unavailable: $($_.Exception.Message)" })
        }
        foreach ($t in $ScopeTags) {
            $Default = if ($t.isBuiltIn -eq $true) { 'Built-in' } else { 'Custom' }
            $r.Add(@('Scope Tag', [string]$t.displayName, $Default, [string]$t.description))
        }

        $RoleDefinitions = @()
        try { $RoleDefinitions = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/roleDefinitions" -tenantid $TenantFilter) } catch {
            $Notes.Add(@{ Section = 'RBAC and Scope Tags'; Detail = "Role definitions unavailable: $($_.Exception.Message)" })
        }
        # Built-in roles are the same in every tenant; only custom roles document anything.
        foreach ($d in ($RoleDefinitions | Where-Object { $_.isBuiltIn -ne $true })) {
            $r.Add(@('Custom Role', [string]$d.displayName, 'Custom role definition', [string]$d.description))
        }

        $Assignments = @()
        try { $Assignments = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/roleAssignments" -tenantid $TenantFilter) } catch {
            $Notes.Add(@{ Section = 'RBAC and Scope Tags'; Detail = "Role assignments unavailable: $($_.Exception.Message)" })
        }
        foreach ($a in $Assignments) {
            $Scope = if ($a.scopeType) { [string]$a.scopeType } else { '' }
            $r.Add(@('Role Assignment', [string]$a.displayName, $Scope, [string]$a.description))
        }

        $CustomRoleCount = @($RoleDefinitions | Where-Object { $_.isBuiltIn -ne $true }).Count
        $State.Count += (@($ScopeTags).Count + $CustomRoleCount + @($Assignments).Count)
        Add-Section 'RBAC' 'RBAC and Scope Tags' 'info' `
            "$(@($ScopeTags).Count) scope tags, $CustomRoleCount custom roles, $(@($Assignments).Count) role assignments. Built-in roles are omitted - they are identical in every tenant." `
            @('Type', 'Name', 'Detail', 'Description') $r `
            'No scope tags, custom roles or delegated role assignments. Intune administration is not delegated in this tenant.'
    }

    # ---- Additional Configurations -------------------------------------------------
    # The long tail: real configuration that lives outside the policy families CIPP caches.
    # Registry-driven so adding an area is one row, and fail-soft per endpoint - a 403 on
    # one of these must never look like "the tenant has none of this".
    Invoke-Section 'AdditionalConfigurations' 'Additional Configurations' {
        $Registry = @(
            @{ Label = 'Policy Set'; Path = '/deviceAppManagement/policySets' }
            @{ Label = 'Terms and Conditions'; Path = '/deviceManagement/termsAndConditions' }
            @{ Label = 'Notification Template'; Path = '/deviceManagement/notificationMessageTemplates' }
            @{ Label = 'Compliance Script'; Path = '/deviceManagement/deviceComplianceScripts' }
            @{ Label = 'macOS Custom Attribute'; Path = '/deviceManagement/deviceCustomAttributeShellScripts' }
            @{ Label = 'Microsoft Tunnel Configuration'; Path = '/deviceManagement/microsoftTunnelConfigurations' }
            @{ Label = 'Microsoft Tunnel Site'; Path = '/deviceManagement/microsoftTunnelSites' }
            @{ Label = 'Hardware Configuration'; Path = '/deviceManagement/hardwareConfigurations' }
            @{ Label = 'Mobile Threat Defense Connector'; Path = '/deviceManagement/mobileThreatDefenseConnectors'; Name = 'partnerState' }
            @{ Label = 'Device Management Partner'; Path = '/deviceManagement/deviceManagementPartners'; Name = 'partnerAppType' }
            @{ Label = 'Remote Assistance Partner'; Path = '/deviceManagement/remoteAssistancePartners' }
            @{ Label = 'iOS LOB Provisioning Profile'; Path = '/deviceAppManagement/iosLobAppProvisioningConfigurations' }
            @{ Label = 'VPP Token'; Path = '/deviceAppManagement/vppTokens'; Name = 'appleId' }
        )

        $r = New-RowList
        $Found = 0
        foreach ($Entry in $Registry) {
            try {
                $Items = @(New-GraphGetRequest -uri "$GraphBeta$($Entry.Path)" -tenantid $TenantFilter)
                foreach ($i in $Items) {
                    $NameProp = if ($Entry.Name) { $Entry.Name } else { 'displayName' }
                    $Name = if ($i.$NameProp) { [string]$i.$NameProp } elseif ($i.displayName) { [string]$i.displayName } else { '(unnamed)' }
                    $Modified = if ($i.lastModifiedDateTime) {
                        try { ([datetime]$i.lastModifiedDateTime).ToString('yyyy-MM-dd') } catch { '' }
                    } else { '' }
                    $r.Add(@($Entry.Label, $Name, [string]$i.description, $Modified))
                    $Found++
                }
            } catch {
                # A 404 on these endpoints usually means the feature is not enabled in the
                # tenant, which is not a failure. Anything else is worth recording.
                $Message = $_.Exception.Message
                if ($Message -notmatch '404|NotFound|ResourceNotFound') {
                    $Notes.Add(@{ Section = 'Additional Configurations'; Detail = "$($Entry.Label) ($($Entry.Path)): $Message" })
                }
            }
        }

        $State.Count += $Found
        Add-Section 'AdditionalConfigurations' 'Additional Configurations' 'info' `
            "$Found objects across $($Registry.Count) additional configuration areas." `
            @('Area', 'Name', 'Description', 'Modified') $r `
            'None of the additional configuration areas are in use in this tenant.'
    }

    # ---- executive findings --------------------------------------------------------
    $ComplianceCount = @(Select-Family @('deviceCompliancePolicies')).Count
    if ($ComplianceCount -eq 0) {
        Add-Finding 'Compliance policies' 'fail' 'No device compliance policies exist, so no device can be evaluated as compliant or non-compliant.'
    } else {
        Add-Finding 'Compliance policies' 'pass' "$ComplianceCount compliance policies are configured."
    }

    $Unassigned = @($Policies | Where-Object { $_.isAssigned -eq $false })
    if ($Unassigned.Count -gt 0) {
        Add-Finding 'Unassigned policies' 'warn' "$($Unassigned.Count) policies exist but are not assigned to any group, so they have no effect: $((@($Unassigned | ForEach-Object { if ($_.displayName) { $_.displayName } else { $_.name } }) | Select-Object -First 8) -join ', ')."
    } else {
        Add-Finding 'Unassigned policies' 'pass' 'Every policy is assigned to at least one group.'
    }

    Add-Finding 'Objects documented' 'info' "$($State.Count) Intune configuration objects captured for $TenantName."

    if ($Notes.Count -gt 0) {
        Add-Finding 'Collection warnings' 'warn' "$($Notes.Count) section(s) could not be read in full. See collection notes."
    }

    return @{
        Title           = 'Intune Configuration Document'
        TenantName      = $TenantName
        TenantDomain    = $DefaultDomain
        GeneratedDate   = (Get-Date).ToString('dd MMMM yyyy')
        Findings        = $Findings
        Sections        = $Sections
        CollectionNotes = $Notes
        ObjectCount     = $State.Count
    }
}
