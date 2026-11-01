function Invoke-ListGuestInventory {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.Read
    .SYNOPSIS
        Guest inventory with origin, redemption state, memberships and a recommended cleanup action
    .DESCRIPTION
        Read only. Lists every guest in one tenant with invitation state and age, sign-in activity (Entra ID P1 tenants),
        account type (personal Microsoft account, email one-time passcode, work/school), consumer email domains, the
        inviting user and whether that user is still enabled, group and Team memberships, and a recommended action
        (REMOVE, DISABLE, REVIEW, KEEP) with the reason. Also returns tenant context: SharePoint/OneDrive Entra B2B
        integration, SharePoint sharing level, who may invite guests and the guest user role. Single tenant only.
        Aspendora fork addition (Vikunja CIPP-14).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # The tenant to inventory. AllTenants is not supported.
    $TenantFilter = $Request.Query.tenantFilter
    # Days without a sign-in before an enabled guest is recommended for DISABLE. Defaults to 90.
    $StaleDays = if ($Request.Query.staleDays -as [int]) { [int]$Request.Query.staleDays } else { 90 }
    # Days an invitation may stay unredeemed before the guest is recommended for REMOVE. Defaults to 30.
    $PendingDays = if ($Request.Query.pendingDays -as [int]) { [int]$Request.Query.pendingDays } else { 30 }

    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [System.Net.HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Select a single tenant: the guest inventory is read live per tenant.' }
            })
    }

    try {
        $Body = Get-CIPPGuestInventory -TenantFilter $TenantFilter -StaleDays $StaleDays -PendingDays $PendingDays
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to build the guest inventory: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::InternalServerError
        $Body = @{ Results = "Failed to build the guest inventory: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
