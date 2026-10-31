function Invoke-ListPhishResistantMfa {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.Read
    .SYNOPSIS
        Phishing-resistant MFA report for a tenant's admins
    .DESCRIPTION
        Lists every holder of a privileged directory role (Global, Privileged Role, Privileged Authentication,
        Security, Exchange, SharePoint, User, Authentication, Conditional Access, Application, Cloud Application,
        Intune, Helpdesk and Billing Administrator), active and PIM-eligible, with group assignments expanded, and
        whether each has a phishing-resistant method (passkey/FIDO2, Windows Hello for Business, Platform Credential,
        certificate). Flags admins without one, admin accounts that also have a licence or mailbox, a Global Admin
        count outside 2-4, passkeys disabled or not self-service, AAGUID restrictions that block Microsoft
        Authenticator passkeys, and a disabled registration campaign. Returns Summary, Admins, Findings and Errors.
        Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-7).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    try {
        $Report = Get-CIPPPhishResistantPosture -TenantFilter $TenantFilter
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)" } })
    }
}
