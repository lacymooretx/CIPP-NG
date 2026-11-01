function Invoke-CIPPStandardMDMEnrollmentDuringRegistration {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) MDMEnrollmentDuringRegistration
    .SYNOPSIS
        (Label) Configure MDM enrollment when adding work or school account
    .DESCRIPTION
        (Helptext) Controls the "Allow my organization to manage my device" prompt when adding a work or school account on Windows (Intune: Devices > Windows > Enrollment > Automatic Enrollment > "Disable MDM enrollment when adding work or school account on Windows"). With the switch on, a user who adds a work account on a personal PC gets the device Entra registered only, not MDM enrolled: they keep single sign-on to Office and Teams, but Intune does not manage or wipe the PC and device-based Conditional Access treats it as unmanaged. Entra join, Autopilot and enrollment through Company Portal are not affected.
        (DocsDescription) Sets `isMdmEnrollmentDuringRegistrationDisabled` on the Microsoft Intune MDM policy (Graph beta `policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000`). When disabled, Windows no longer offers MDM enrollment in the Entra account registration flow, so adding a work account to a personal PC registers the device without enrolling it. This stops accidental BYOD enrollment that the default Windows platform restriction (personally owned devices blocked, see DefaultPlatformRestrictions) would otherwise reject with an enrollment error. Corporate enrollment paths (Entra join, Autopilot, Company Portal, GPO auto-enrollment of hybrid joined devices) are unchanged. Remediation reads the policy back after the PATCH, because Graph can accept the write and leave the value unchanged. Use the Personal Devices report (Endpoint > Reports) to see personally owned devices that are already enrolled.
    .NOTES
        CAT
            Intune Standards
        TAG
        EXECUTIVETEXT
            Controls automatic device management enrollment during work account setup. When disabled, users can add work accounts to their Windows devices without the prompt asking to allow organizational device management, preventing unintended MDM enrollments on personal or BYOD devices.
        ADDEDCOMPONENT
            {"type":"switch","name":"standards.MDMEnrollmentDuringRegistration.disableEnrollment","label":"Disable MDM enrollment during registration"}
        IMPACT
            Medium Impact
        ADDEDDATE
            2025-12-15
        POWERSHELLEQUIVALENT
            Graph API
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
    $TestResult = Test-CIPPStandardLicense -StandardName 'MDMEnrollmentDuringRegistration' -TenantFilter $Tenant -Preset Intune

    if ($TestResult -eq $false) {
        return $true
    }

    try {
        $CurrentInfo = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000' -tenantid $Tenant
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Standards' -Tenant $Tenant -Message "Could not get MDM enrollment during registration state for $Tenant. Error: $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
        return
    }

    # Get the current state - if the property doesn't exist, treat as false (default behavior)
    # -eq $true rather than [bool]: a string 'false' from a stored template would cast to $true.
    $CurrentState = ($CurrentInfo.isMdmEnrollmentDuringRegistrationDisabled -eq $true)
    $DesiredState = ($Settings.disableEnrollment -eq $true)
    $StateIsCorrect = $CurrentState -eq $DesiredState
    $stateText = $DesiredState ? 'disabled' : 'enabled'

    if ($Settings.remediate -eq $true) {
        if ($StateIsCorrect -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "MDM enrollment during registration is already $stateText" -sev Info
        } else {
            $GraphParam = @{
                tenantid = $Tenant
                Uri      = 'https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000'
                type     = 'PATCH'
                Body     = (@{'isMdmEnrollmentDuringRegistrationDisabled' = $DesiredState } | ConvertTo-Json)
            }

            try {
                $null = New-GraphPostRequest @GraphParam
                # Aspendora fork (Vikunja CIPP-21): a 2xx from Graph is not proof the change applied, so read the
                # policy back before claiming success and report what is actually stored.
                $After = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/0000000a-0000-0000-c000-000000000000' -tenantid $Tenant
                $AfterState = ($After.isMdmEnrollmentDuringRegistrationDisabled -eq $true)
                if ($AfterState -eq $DesiredState) {
                    $CurrentState = $AfterState
                    $StateIsCorrect = $true
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "Successfully $stateText MDM enrollment during registration (read back)" -sev Info
                } else {
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "MDMEnrollmentDuringRegistration: Graph accepted the change but isMdmEnrollmentDuringRegistrationDisabled still reads '$($After.isMdmEnrollmentDuringRegistrationDisabled)'." -sev Error
                }
            } catch {
                $ErrorMessage = Get-CippException -Exception $_
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to configure MDM enrollment during registration. Error: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
            }
        }
    }

    if ($Settings.alert -eq $true) {
        if ($StateIsCorrect -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $tenant -message "MDM enrollment during registration is $stateText as configured" -sev Info
        } else {
            Write-StandardsAlert -message "MDM enrollment during registration is not $stateText" -object @{isMdmEnrollmentDuringRegistrationDisabled = $CurrentState; desiredState = $DesiredState } -tenant $tenant -standardName 'MDMEnrollmentDuringRegistration' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $tenant -message "MDM enrollment during registration is not $stateText" -sev Info
        }
    }

    if ($Settings.report -eq $true) {
        $CurrentValue = @{
            isMdmEnrollmentDuringRegistrationDisabled = $CurrentState
        }
        $ExpectedValue = @{
            isMdmEnrollmentDuringRegistrationDisabled = $DesiredState
        }
        Set-CIPPStandardsCompareField -FieldName 'standards.MDMEnrollmentDuringRegistration' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -TenantFilter $Tenant
    }
}
