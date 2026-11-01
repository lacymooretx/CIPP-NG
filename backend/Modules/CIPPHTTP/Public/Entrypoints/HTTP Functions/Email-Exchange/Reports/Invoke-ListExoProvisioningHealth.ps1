function Invoke-ListExoProvisioningHealth {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Exchange.Mailbox.Read
    .SYNOPSIS
        Check that Exchange Online provisioned correctly in one tenant (organisation, RBAC, accepted domains, mailboxes)
    .DESCRIPTION
        Read only. Runs Get-CIPPExoProvisioningHealth against one tenant and returns one row per check
        (Check, Status Pass/Warn/Fail/Info, Detail, Fix, Errored) plus a Summary: Get-OrganizationConfig answers
        (and IsDehydrated), the built-in role groups and core management roles exist, Organization Management holds
        its expected roles (the comparison the Tenant Access check and ExecExchangeRoleRepair use), verified Entra
        email domains are accepted domains, and users licensed for a mailbox for longer than graceHours have an
        Exchange recipient. Also returns MissingDomains, UsersWithoutMailbox, LicensedMailUsers and
        MissingOrgManagementRoles. A tenant without an Exchange licence returns Info rows, not failures. Nothing is
        repaired here: when Organization Management roles are missing, Summary.RepairSuggested is true and the
        repair is a separate, confirmed call to ExecExchangeRoleRepair. Single tenant only.
        Aspendora fork addition (Vikunja CIPP-36).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # The tenant to check. AllTenants is not supported.
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    # Hours a user must have held a mailbox licence before a missing mailbox is reported. Defaults to 24, 1-720.
    $GraceIn = $Request.Query.graceHours ?? $Request.Body.graceHours
    $GraceHours = 24
    if ($GraceIn -as [int]) { $GraceHours = [math]::Min(720, [math]::Max(1, [int]$GraceIn)) }

    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [System.Net.HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Select a single tenant: the Exchange provisioning check is read live per tenant.' }
            })
    }

    try {
        $Body = Get-CIPPExoProvisioningHealth -TenantFilter $TenantFilter -GraceHours $GraceHours
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to check Exchange provisioning: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::InternalServerError
        $Body = @{ Results = "Failed to check Exchange provisioning: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
