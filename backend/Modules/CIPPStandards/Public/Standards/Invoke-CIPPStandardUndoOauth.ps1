function Invoke-CIPPStandardUndoOauth {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) UndoOauth
    .SYNOPSIS
        (Label) Undo App Consent Standard
    .DESCRIPTION
        (Helptext) Disables App consent and set to Allow user consent for apps
        (DocsDescription) Disables App consent and set to Allow user consent for apps
    .NOTES
        CAT
            Entra (AAD) Standards
        TAG
        EXECUTIVETEXT
            Reverses application consent restrictions, allowing employees to approve applications independently without administrative oversight. This increases productivity and user autonomy but reduces security controls over data access permissions.
        ADDEDCOMPONENT
        IMPACT
            High Impact
        ADDEDDATE
            2022-01-07
        POWERSHELLEQUIVALENT
            Update-MgPolicyAuthorizationPolicy
        RECOMMENDEDBY
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/alignment/templates/available-standards
    #>

    param($Tenant, $Settings)

    try {
        $CurrentState = New-GraphGetRequest -tenantid $Tenant -Uri 'https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy?$select=permissionGrantPolicyIdsAssignedToDefaultUserRole'
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'Standards' -Tenant $Tenant -Message "Could not get the App Consent state for $Tenant. Error: $ErrorMessage" -Sev Error
        return
    }

    # -contains, not -eq. This property is an ARRAY, and `$array -eq 'x'` returns the matching
    # ELEMENT (an Object[]), not a boolean - so the later `if ($StateIsCorrect -eq $true)` compared a
    # string against 'True' and was never satisfied. The consequences were that the "already
    # disabled" branch never ran (so a compliant tenant was re-PATCHed on every cycle) and the alert
    # and report always claimed the standard was not applied.
    $StateIsCorrect = (@($CurrentState.permissionGrantPolicyIdsAssignedToDefaultUserRole) -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy')

    if ($Settings.remediate -eq $true) {
        if ($StateIsCorrect -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Application Consent Mode is already disabled.' -sev Info
        } else {
            try {
                $GraphRequest = @{
                    tenantid    = $tenant
                    uri         = 'https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy'
                    AsApp       = $false
                    Type        = 'PATCH'
                    ContentType = 'application/json'
                    Body        = '{"permissionGrantPolicyIdsAssignedToDefaultUserRole":["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}'
                }
                New-GraphPostRequest @GraphRequest

                # Read back before claiming success. A tenant in Microsoft-managed consent mode
                # ("Let Microsoft manage your consent settings") accepts this PATCH, returns 204 and
                # discards it - Microsoft owns the assignment there, so the property is effectively
                # read-only. Without this check the standard reported success, and $StateIsCorrect
                # below still held its PRE-remediation value, so the alert and report agreed with it.
                # See docs/todo-cipp-bugs.md 5b.
                $PostState = New-GraphGetRequest -tenantid $Tenant -Uri 'https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy?$select=permissionGrantPolicyIdsAssignedToDefaultUserRole'
                $Assigned = @($PostState.permissionGrantPolicyIdsAssignedToDefaultUserRole)
                $StateIsCorrect = ($Assigned -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy')

                if ($StateIsCorrect) {
                    Write-LogMessage -API 'Standards' -tenant $tenant -message 'Application Consent Mode has been disabled.' -sev Info
                } else {
                    # The pair below is the fingerprint of Microsoft-managed consent mode.
                    $ManagedMode = ($Assigned -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-recommended') -and
                                   ($Assigned -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps')
                    $Reason = if ($ManagedMode) {
                        'the tenant is in Microsoft-managed consent mode, where Microsoft owns this assignment and silently discards writes to it. Resolve individual applications with per-app admin consent instead.'
                    } else {
                        'the write was accepted but the value did not change.'
                    }
                    Write-LogMessage -API 'Standards' -tenant $tenant -message "Application Consent Mode could NOT be disabled: $Reason Current value: $($Assigned -join ', ')" -sev Error
                }
            } catch {
                Write-LogMessage -API 'Standards' -tenant $tenant -message 'Failed to set Application Consent Mode to disabled.' -sev Error -LogData $_
            }
        }

    }

    if ($Settings.alert -eq $true) {
        if ($StateIsCorrect -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Application Consent Mode is disabled.' -sev Info
        } else {
            Write-StandardsAlert -message 'Application Consent Mode is not disabled.' -object $CurrentState -tenant $Tenant -standardName 'UndoOauth' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Application Consent Mode is not disabled.' -sev Info
        }
    }

    if ($Settings.report -eq $true) {
        Add-CIPPBPAField -FieldName 'UndoOauth' -FieldValue $StateIsCorrect -StoreAs bool -Tenant $tenant
        $CurrentValue = @{
            permissionGrantPolicyIdsAssignedToDefaultUserRole = $CurrentState.permissionGrantPolicyIdsAssignedToDefaultUserRole
        }
        $ExpectedValue = @{
            permissionGrantPolicyIdsAssignedToDefaultUserRole = @('ManagePermissionGrantsForSelf.microsoft-user-default-legacy')
        }
        Set-CIPPStandardsCompareField -FieldName 'standards.UndoOauth' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -Tenant $Tenant
    }
}
