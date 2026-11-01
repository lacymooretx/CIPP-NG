function Get-CIPPAlertFailureSeverity {
    <#
    .SYNOPSIS
        Severity to log an alert's failure at: Info when the tenant simply lacks the licence, Error otherwise
    .DESCRIPTION
        Scheduled alerts run on a tenant group, so some tenants will not have the licence a check needs
        (Defender for Office 365 Plan 2, Entra ID P1/P2, Intune...). Graph answers those with a licensing
        error every run. Logged at Error, the logbook notification rule (Alert/Error) turns each run into an
        email, so a missing licence must be logged at Info. Real failures (auth, throttling, bugs) stay Error.
        Aspendora fork addition (2026-11-01, after the IMTEC Defender pending remediation emails every 4 h).
    .PARAMETER ErrorText
        The NormalizedError (or message) of the failure.
    .OUTPUTS
        'Info' or 'Error'
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$ErrorText)
    $LicencePatterns = @(
        'not provisioned'
        'correct M365 license'
        'AadPremiumLicenseRequired'
        'premium license'
        'Tenant does not have a SPO license'
        'does not have (a |the )?(valid |required )?licen[cs]e'
        'licen[cs]e (is )?required'
        'requires? (an? )?(Entra ID|Azure AD|Microsoft Entra ID) (P1|P2|Premium)'
        'Microsoft Defender for Office 365 Plan 2'
    )
    foreach ($Pattern in $LicencePatterns) {
        if ($ErrorText -match $Pattern) { return 'Info' }
    }
    return 'Error'
}
