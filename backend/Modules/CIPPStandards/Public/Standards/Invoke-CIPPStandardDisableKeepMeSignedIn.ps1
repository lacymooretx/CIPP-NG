function Invoke-CIPPStandardDisableKeepMeSignedIn {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) DisableKeepMeSignedIn
    .SYNOPSIS
        (Label) Hide the 'Stay signed in?' prompt
    .DESCRIPTION
        (Helptext) Turns off the 'Stay signed in?' (KMSI) prompt on the Microsoft sign-in page (company branding 'Show option to remain signed in' = No). With the prompt shown, a user who clicks Yes gets a persistent browser cookie that can keep the session alive for up to 90 days, including on shared or unmanaged computers. The report also says whether a sign-in frequency or 'never persistent browser' Conditional Access session policy is enforced, because the tenant is most exposed when neither control is in place.
        (DocsDescription) Sets `isKeepMeSignedInDisabled` to true on the default company branding localization (Graph beta `organization/{id}/branding/localizations/0`). A tenant with no branding localization shows the prompt (Microsoft's default); remediation creates the default localization with only this setting. Report and alert runs never create branding. Conditional Access policies with an enabled sign-in frequency or a `persistentBrowser` mode of `never` are listed for context; they are not changed by this standard (see the CIPP-8 report-only 'Sign-in frequency 12h and no persistent browser on unmanaged devices' policy). Users on Entra-joined or registered devices keep single sign-on through the Primary Refresh Token, so the main effect is on browsers on unmanaged computers. Aspendora fork addition (Vikunja CIPP-18).
    .NOTES
        CAT
            Entra (AAD) Standards
        TAG
        IMPACT
            Low Impact
        ADDEDDATE
            2026-11-01
        POWERSHELLEQUIVALENT
            Update-MgBetaOrganizationBrandingLocalization -IsKeepMeSignedInDisabled
        RECOMMENDEDBY
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards
    #>

    param($Tenant, $Settings)

    $TenantId = (Get-Tenants -TenantFilter $Tenant | Select-Object -First 1).customerId
    if (-not $TenantId) {
        Write-LogMessage -API 'Standards' -tenant $Tenant -message 'DisableKeepMeSignedIn: could not resolve the tenant ID.' -sev Error
        return
    }
    $BrandingBase = "https://graph.microsoft.com/beta/organization/$TenantId/branding/localizations"

    # A tenant without the default localization ('0') has never saved branding and shows the prompt.
    try {
        $Localizations = @(New-GraphGetRequest -uri $BrandingBase -tenantid $Tenant -AsApp $true)
        $HasDefault = [bool]($Localizations | Where-Object { [string]$_.id -eq '0' })
        $Current = if ($HasDefault) { New-GraphGetRequest -uri "$BrandingBase/0" -tenantid $Tenant -AsApp $true } else { $null }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "DisableKeepMeSignedIn: could not read company branding: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return
    }
    $KmsiDisabled = ($Current.isKeepMeSignedInDisabled -eq $true)

    # Context only: CA session controls that bound session lifetime. A failed read does not stop the standard.
    $SessionPolicies = @()
    try {
        $Policies = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -tenantid $Tenant -AsApp $true)
        $SessionPolicies = @(foreach ($Policy in $Policies) {
                $Sif = $Policy.sessionControls.signInFrequency
                $Pb = $Policy.sessionControls.persistentBrowser
                $HasSif = ($Sif.isEnabled -eq $true -and $Sif.frequencyInterval -ne 'everyTime' -and $Sif.value)
                $HasPb = ($Pb.isEnabled -eq $true -and [string]$Pb.mode -eq 'never')
                if ($HasSif -or $HasPb) {
                    [pscustomobject]@{
                        Name              = [string]$Policy.displayName
                        State             = [string]$Policy.state
                        SignInFrequency   = if ($HasSif) { "$($Sif.value) $($Sif.type)" } else { $null }
                        PersistentBrowser = if ($HasPb) { 'never' } else { $null }
                    }
                }
            })
    } catch {
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "DisableKeepMeSignedIn: could not read Conditional Access policies: $((Get-CippException -Exception $_).NormalizedError)" -sev Info
    }
    $EnforcedSession = @($SessionPolicies | Where-Object { $_.State -eq 'enabled' })

    if ($Settings.remediate -eq $true) {
        if ($KmsiDisabled) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "The 'Stay signed in?' prompt is already hidden." -sev Info
        } else {
            try {
                $Body = @{ isKeepMeSignedInDisabled = $true } | ConvertTo-Json -Compress
                if ($HasDefault) {
                    $null = New-GraphPostRequest -tenantid $Tenant -uri "$BrandingBase/0" -AsApp $true -type PATCH -body $Body -ContentType 'application/json; charset=utf-8'
                } else {
                    $null = New-GraphPostRequest -tenantid $Tenant -uri $BrandingBase -AsApp $true -type POST -body $Body -ContentType 'application/json; charset=utf-8'
                }
                # Graph can accept a branding write and ignore it, so read it back before claiming success.
                $After = New-GraphGetRequest -uri "$BrandingBase/0" -tenantid $Tenant -AsApp $true
                if ($After.isKeepMeSignedInDisabled -eq $true) {
                    $KmsiDisabled = $true
                    $HasDefault = $true
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "Hid the 'Stay signed in?' prompt (company branding isKeepMeSignedInDisabled = true, read back)." -sev Info
                } else {
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "DisableKeepMeSignedIn: Graph accepted the change but isKeepMeSignedInDisabled still reads '$($After.isKeepMeSignedInDisabled)'." -sev Error
                }
            } catch {
                $ErrorMessage = Get-CippException -Exception $_
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to hide the 'Stay signed in?' prompt: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
            }
        }
    }

    if ($Settings.alert -eq $true) {
        if ($KmsiDisabled) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "The 'Stay signed in?' prompt is hidden." -sev Info
        } else {
            $Message = if ($EnforcedSession.Count -eq 0) {
                "The 'Stay signed in?' prompt is shown and no enforced Conditional Access policy limits session lifetime: a persistent sign-in cookie can last up to 90 days."
            } else {
                "The 'Stay signed in?' prompt is shown. Session lifetime is limited by $($EnforcedSession.Count) enforced Conditional Access policy(ies)."
            }
            Write-StandardsAlert -message $Message -object ([pscustomobject]@{
                    isKeepMeSignedInDisabled = $KmsiDisabled
                    BrandingConfigured       = $HasDefault
                    SessionPolicies          = $SessionPolicies
                }) -tenant $Tenant -standardName 'DisableKeepMeSignedIn' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $Tenant -message $Message -sev Info
        }
    }

    if ($Settings.report -eq $true) {
        Set-CIPPStandardsCompareField -FieldName 'standards.DisableKeepMeSignedIn' -CurrentValue @{ isKeepMeSignedInDisabled = $KmsiDisabled } -ExpectedValue @{ isKeepMeSignedInDisabled = $true } -Tenant $Tenant
    }
}
