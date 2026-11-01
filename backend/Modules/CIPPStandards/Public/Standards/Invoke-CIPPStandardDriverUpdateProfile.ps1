function Invoke-CIPPStandardDriverUpdateProfile {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) DriverUpdateProfile
    .SYNOPSIS
        (Label) Standardize the Windows driver and firmware update profile
    .DESCRIPTION
        (Helptext) **Requires Windows Enterprise E3/E5 or Microsoft 365 Business Premium rights and Windows Update for Business deployment service / Autopatch onboarding.** Makes sure the tenant has a Windows driver update profile with the chosen approval method (automatic or manual) and, for automatic approval, the chosen deferral. Remediation creates the profile unassigned; assign it yourself. Tenants managed by Windows Autopatch can be treated as compliant.
        (DocsDescription) Checks deviceManagement/windowsDriverUpdateProfiles for a profile with the configured name. Report and alert compare its approval type and deferral days with the template, list Autopatch-managed and other driver profiles, and count update rings or Settings Catalog policies that block Windows Update drivers (which silently defeat any driver profile). Remediation creates the profile when it is missing (no assignments) and corrects the deferral of an automatic profile. Intune does not allow the approval type of an existing profile to change, so a mismatch is only logged. When "Treat a Windows Autopatch driver profile as compliant" is on, a tenant whose driver updates are managed by Autopatch is compliant and nothing is created. Aspendora fork addition (Vikunja CIPP-24).
    .NOTES
        CAT
            Intune Standards
        TAG
        EXECUTIVETEXT
            Keeps Windows driver and firmware updates under a consistent, deliberate approval policy in every tenant, so hardware drivers are either approved automatically after a short soak period or held for review, instead of each tenant drifting to its own setup.
        ADDEDCOMPONENT
            {"type":"textField","name":"standards.DriverUpdateProfile.ProfileName","label":"Driver update profile name","required":false,"defaultValue":"CIPP - Windows Driver Updates"}
            {"type":"autoComplete","multiple":false,"creatable":false,"name":"standards.DriverUpdateProfile.ApprovalType","label":"Approval type","options":[{"label":"Automatic (approve recommended drivers after the deferral)","value":"automatic"},{"label":"Manual (every driver needs review)","value":"manual"}],"defaultValue":{"label":"Automatic (approve recommended drivers after the deferral)","value":"automatic"}}
            {"type":"number","name":"standards.DriverUpdateProfile.DeferralDays","label":"Deferral days for automatic approval (0-30, default 7)","defaultValue":7,"validators":{"min":{"value":0,"message":"Minimum value is 0"},"max":{"value":30,"message":"Intune accepts a driver deferral of 0 to 30 days"}}}
            {"type":"switch","name":"standards.DriverUpdateProfile.AcceptAutopatch","label":"Treat a Windows Autopatch driver profile as compliant","defaultValue":true}
        IMPACT
            Medium Impact
        ADDEDDATE
            2026-10-31
        POWERSHELLEQUIVALENT
            Graph API - deviceManagement/windowsDriverUpdateProfiles
        RECOMMENDEDBY
        REQUIREDCAPABILITIES
            "INTUNE_A"
            "MDM_Services"
            "EMS"
            "SCCM"
            "MICROSOFTINTUNEPLAN1"
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/alignment/templates/available-standards
    #>

    param($Tenant, $Settings)

    $TestResult = Test-CIPPStandardLicense -StandardName 'DriverUpdateProfile' -TenantFilter $Tenant -Preset Intune
    if ($TestResult -eq $false) { return $true }

    $ProfileName = ([string]($Settings.ProfileName)).Trim()
    if (-not $ProfileName) { $ProfileName = 'CIPP - Windows Driver Updates' }
    $ApprovalType = ([string]($Settings.ApprovalType.value ?? $Settings.ApprovalType ?? 'automatic')).ToLowerInvariant()
    if ($ApprovalType -notin @('automatic', 'manual')) { $ApprovalType = 'automatic' }
    $DeferralDays = 7
    if ($null -ne $Settings.DeferralDays -and [string]$Settings.DeferralDays -ne '') {
        $Parsed = 0
        if ([int]::TryParse([string]$Settings.DeferralDays, [ref]$Parsed)) { $DeferralDays = [math]::Min([math]::Max($Parsed, 0), 30) }
    }
    $AcceptAutopatch = ConvertTo-CIPPBoolean $Settings.AcceptAutopatch -Default $true

    try {
        $Profiles = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles' -tenantid $Tenant -ErrorAction Stop)
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "DriverUpdateProfile: could not read driver update profiles (needs Windows E3/E5 or Business Premium rights and WUfB deployment service onboarding): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return
    }

    $State = Test-CIPPDriverUpdateProfileState -Profiles $Profiles -ProfileName $ProfileName -ApprovalType $ApprovalType -DeferralDays $DeferralDays -AcceptAutopatch $AcceptAutopatch

    # Remediation only runs when the template sets remediate; report and alert never write anything.
    if ($Settings.remediate -eq $true) {
        switch ($State.Action) {
            'Create' {
                $Body = [ordered]@{
                    displayName  = $ProfileName
                    description  = 'Driver and firmware update profile managed by the CIPP DriverUpdateProfile standard.'
                    approvalType = $ApprovalType
                }
                if ($ApprovalType -eq 'automatic') { $Body.deploymentDeferralInDays = $DeferralDays }
                try {
                    $Created = New-GraphPostRequest -tenantid $Tenant -uri 'https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles' -type POST -body ($Body | ConvertTo-Json -Compress) -ContentType 'application/json'
                    # Read back: a 2xx is not proof the profile exists with the values we sent.
                    $Profiles = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles' -tenantid $Tenant)
                    $State = Test-CIPPDriverUpdateProfileState -Profiles $Profiles -ProfileName $ProfileName -ApprovalType $ApprovalType -DeferralDays $DeferralDays -AcceptAutopatch $AcceptAutopatch
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "DriverUpdateProfile: created '$ProfileName' ($ApprovalType$(if ($ApprovalType -eq 'automatic') { ", $DeferralDays day deferral" }); id $($Created.id)). It has no assignments: assign it to the device groups it should cover." -sev Info
                } catch {
                    $ErrorMessage = Get-CippException -Exception $_
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "DriverUpdateProfile: failed to create '$ProfileName': $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
                }
            }
            'UpdateDeferral' {
                try {
                    $null = New-GraphPostRequest -tenantid $Tenant -uri "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles/$($State.ProfileId)" -type PATCH -body (@{ deploymentDeferralInDays = $DeferralDays } | ConvertTo-Json -Compress) -ContentType 'application/json'
                    $Profiles = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles' -tenantid $Tenant)
                    $State = Test-CIPPDriverUpdateProfileState -Profiles $Profiles -ProfileName $ProfileName -ApprovalType $ApprovalType -DeferralDays $DeferralDays -AcceptAutopatch $AcceptAutopatch
                    $Sev = if ($State.Compliant -eq $true) { 'Info' } else { 'Warning' }
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "DriverUpdateProfile: set the deferral of '$ProfileName' to $DeferralDays day(s); read back $($State.CurrentDeferral)." -sev $Sev
                } catch {
                    $ErrorMessage = Get-CippException -Exception $_
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "DriverUpdateProfile: failed to update the deferral of '$ProfileName': $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
                }
            }
            'ApprovalTypeMismatch' {
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "DriverUpdateProfile: '$ProfileName' uses $($State.CurrentType) approval but the template wants $ApprovalType. Intune cannot change the approval type of an existing profile; create a new one (or rename this one and let remediation create it) and move the assignments." -sev Warning
            }
            default {
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "DriverUpdateProfile: already in the desired state ($($State.Action))." -sev Info
            }
        }
    }

    $Blocking = $null
    if ($Settings.alert -eq $true -or $Settings.report -eq $true) {
        try { $Blocking = Get-CIPPDriverBlockingPolicies -TenantFilter $Tenant } catch { $Blocking = $null }
    }
    $BlockingAssigned = @($Blocking.Findings | Where-Object { $_.Assigned -eq $true })

    $CurrentValue = [ordered]@{
        ProfilePresent          = [bool]$State.ProfileId -or $State.Action -eq 'AutopatchManaged'
        ApprovalType            = if ($State.Action -eq 'AutopatchManaged') { 'autopatch' } else { $State.CurrentType }
        DeferralDays            = $State.CurrentDeferral
        AutopatchProfiles       = @($State.AutopatchProfiles)
        AssignedBlockingPolicies = @($BlockingAssigned | ForEach-Object { $_.PolicyName })
    }
    $ExpectedValue = [ordered]@{
        ProfilePresent          = $true
        ApprovalType            = if ($State.Action -eq 'AutopatchManaged') { 'autopatch' } else { $ApprovalType }
        DeferralDays            = if ($State.Action -eq 'AutopatchManaged') { $State.CurrentDeferral } else { $State.ExpectedDeferral }
        AutopatchProfiles       = @($State.AutopatchProfiles)
        AssignedBlockingPolicies = @()
    }
    $AllGood = ($State.Compliant -eq $true) -and $BlockingAssigned.Count -eq 0

    if ($Settings.alert -eq $true) {
        if ($AllGood) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "DriverUpdateProfile: driver update profile is in the desired state ($($State.Action))." -sev Info
        } else {
            $Why = switch ($State.Action) {
                'Create' { "no driver update profile named '$ProfileName'" }
                'UpdateDeferral' { "'$ProfileName' defers drivers $($State.CurrentDeferral) day(s), expected $DeferralDays" }
                'ApprovalTypeMismatch' { "'$ProfileName' uses $($State.CurrentType) approval, expected $ApprovalType" }
                default { 'profile is in the desired state' }
            }
            if ($BlockingAssigned.Count -gt 0) { $Why = "$Why; drivers are blocked by $(@($BlockingAssigned.PolicyName) -join ', ')" }
            Write-StandardsAlert -message "Windows driver update profile is not in the desired state: $Why." -object $CurrentValue -tenant $Tenant -standardName 'DriverUpdateProfile' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "DriverUpdateProfile: not in the desired state: $Why." -sev Info
        }
    }

    if ($Settings.report -eq $true) {
        Set-CIPPStandardsCompareField -FieldName 'standards.DriverUpdateProfile' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -TenantFilter $Tenant
    }
}
