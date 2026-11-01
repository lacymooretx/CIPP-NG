function Invoke-ListRoleAssignmentReport {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.Role.Read
    .SYNOPSIS
        Standing-admin and least-privilege report for a tenant's directory roles
    .DESCRIPTION
        Lists every directory role assignment, active (permanent or PIM time-bound) and PIM-eligible, with group
        assignments expanded, last sign-in and break-glass status. Flags permanent Global Administrators other than
        registered break-glass accounts (with a least-privilege suggestion from their recent Entra audit activity),
        service principals and guests holding roles, privileged accounts with no recent sign-in, disabled accounts
        still holding roles, and GDAP relationships with this customer that carry Global Administrator. PIM needs
        Entra ID P2 and sign-in activity Entra ID P1; without them those parts are reported as unknown, not as
        findings. Returns Summary, Assignments, Recommendations, Findings, Tasks (the task-to-least-privileged-role
        lookup from Config/LeastPrivilegeRoles.json) and Errors.
        Optional: InactiveDays (default 45). Report only: nothing is changed. Aspendora fork addition (Vikunja CIPP-15).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::BadRequest; Body = @{ Results = 'Pick a single tenant.' } })
    }
    $InactiveDays = 45
    $Raw = [string]($Request.Query.InactiveDays ?? $Request.Body.InactiveDays)
    $Parsed = 0
    if ($Raw -and [int]::TryParse($Raw, [ref]$Parsed) -and $Parsed -gt 0) { $InactiveDays = $Parsed }
    try {
        $Report = Get-CIPPRoleAssignmentReport -TenantFilter $TenantFilter -InactiveDays $InactiveDays
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::OK; Body = $Report })
    } catch {
        return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::InternalServerError; Body = @{ Results = "Failed: $((Get-CippException -Exception $_).NormalizedError)" } })
    }
}
