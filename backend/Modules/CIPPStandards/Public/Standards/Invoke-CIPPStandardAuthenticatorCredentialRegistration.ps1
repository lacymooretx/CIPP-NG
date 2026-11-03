function Invoke-CIPPStandardAuthenticatorCredentialRegistration {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) AuthenticatorCredentialRegistration
    .SYNOPSIS
        (Label) Provision the Microsoft Authenticator Credential Registration app
    .DESCRIPTION
        (Helptext) Creates the service principal for Microsoft Authenticator Credential Registration (6aa00308-ea33-4caa-90d6-ae905d8cb51b), so the resource can be selected in Conditional Access. Without it, a template that excludes this app has nothing to exclude. Provisioning changes no Conditional Access policy.
        (DocsDescription) Microsoft Learn documents that registering a passkey in Microsoft Authenticator is blocked by an All resources Conditional Access policy that requires a phishing-resistant authentication strength, an approved client app or an app protection policy, and that the fix is to exclude this resource after provisioning it. This standard reads the service principal and creates it when absent. It never changes a Conditional Access policy and never enables a service principal someone has disabled; a disabled one is reported as not compliant. The Conditional Access gap analysis lists the policies that actually block registration.
    .NOTES
        CAT
            Entra (AAD) Standards
        TAG
        IMPACT
            Low Impact
        ADDEDDATE
            2026-11-03
        POWERSHELLEQUIVALENT
            New-MgServicePrincipal -AppId 6aa00308-ea33-4caa-90d6-ae905d8cb51b
        RECOMMENDEDBY
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards
    #>

    param($Tenant, $Settings)

    $AppId = '6aa00308-ea33-4caa-90d6-ae905d8cb51b'
    $FieldName = 'standards.AuthenticatorCredentialRegistration'
    $Remediate = $Settings.remediate -eq $true

    $Sp = Confirm-CIPPServicePrincipal -TenantFilter $Tenant -AppId $AppId -Provision:$Remediate

    if ($Sp.State -eq 'Unknown') {
        # "Could not check" must not read as absent or as compliant.
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorCredentialRegistration: could not read the service principal: $($Sp.Error)" -sev Error
        if ($Settings.report -eq $true) {
            Set-CIPPStandardsCompareField -FieldName $FieldName -CurrentValue @{ Error = "Could not read the service principal: $($Sp.Error)" } -ExpectedValue @{ ServicePrincipalPresent = $true; AccountEnabled = $true } -Tenant $Tenant
        }
        return
    }

    # An unread accountEnabled (still waiting on the read-back) is not a disabled app.
    $Compliant = $Sp.Present -and $Sp.AccountEnabled -ne $false

    if ($Remediate) {
        switch ($Sp.State) {
            'Created' {
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorCredentialRegistration: created the service principal ($($Sp.Method) token) and read it back." -sev Info
            }
            'CreatedPendingReadBack' {
                Write-LogMessage -API 'Standards' -tenant $Tenant -message 'AuthenticatorCredentialRegistration: Graph accepted the service principal but it is not readable yet. Directory reads can lag; the next run confirms it.' -sev Info
            }
            'Failed' {
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorCredentialRegistration: could not create the service principal: $($Sp.Error)" -sev Error
            }
            default {
                if ($Compliant) {
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message 'AuthenticatorCredentialRegistration: the service principal already exists.' -sev Info
                } else {
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message 'AuthenticatorCredentialRegistration: the service principal exists but is disabled. It was left as it is; enable it if that was not deliberate.' -sev Warning
                }
            }
        }
        if ($Sp.Created) {
            # New-CIPPCAPolicy batches and the gap analysis read service principals from the cache.
            try {
                Set-CIPPDBCacheServicePrincipals -TenantFilter $Tenant
            } catch {
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "AuthenticatorCredentialRegistration: could not refresh the service principals cache: $($_.Exception.Message)" -sev Warning
            }
        }
    }

    if ($Settings.alert -eq $true) {
        if ($Compliant) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'AuthenticatorCredentialRegistration: the service principal is present and enabled.' -sev Info
        } else {
            $Message = if ($Sp.Present) {
                'AuthenticatorCredentialRegistration: the service principal exists but is disabled.'
            } else {
                'AuthenticatorCredentialRegistration: the service principal is not in this tenant, so it cannot be excluded in Conditional Access.'
            }
            Write-StandardsAlert -message $Message -object ([pscustomobject]@{ AppId = $AppId; State = $Sp.State; AccountEnabled = $Sp.AccountEnabled; Error = $Sp.Error }) -tenant $Tenant -standardName 'AuthenticatorCredentialRegistration' -standardId $Settings.standardId
        }
    }

    if ($Settings.report -eq $true) {
        $CurrentValue = [pscustomobject]@{ ServicePrincipalPresent = [bool]$Sp.Present; AccountEnabled = ($Sp.Present -and $Sp.AccountEnabled -ne $false) }
        $ExpectedValue = [pscustomobject]@{ ServicePrincipalPresent = $true; AccountEnabled = $true }
        Set-CIPPStandardsCompareField -FieldName $FieldName -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -Tenant $Tenant
    }
}
