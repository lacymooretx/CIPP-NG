function Invoke-ListSignInExplanation {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.Read
    .SYNOPSIS
        Explains a user's failed sign-ins in plain language: error code, Conditional Access result, MFA source, device, risk and the fix
    .DESCRIPTION
        Read only, single tenant. Give userPrincipalName (with hours, default 24, max 720) or correlationId (a sign-in
        correlation ID or request ID, searched over the last 30 days). Reads beta auditLogs/signIns (interactive;
        non-interactive too with includeNonInteractive=true), keeps the newest failures and interrupts plus the
        latest success, and for each returns the time (US Central and UTC), app, client app and whether it is legacy
        authentication, IP and location, device (compliant / managed / join type), the AADSTS code with
        Microsoft's failure reason, a plain-English explanation and fix, every Conditional Access policy that was
        evaluated with its result and, for failed ones, the enforced controls and matched conditions. Also returns
        the user's per-user MFA state, security defaults, a wrong-password / lockout summary across the window, and
        a Markdown SummaryText for copying or posting to ConnectWise (see ExecSignInExplanationNote). Tenants without
        Entra ID P1 have no sign-in logs: the result then has LicenseRequired=true and a message.
        Aspendora fork addition (Vikunja CIPP-10).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    # The tenant to read. AllTenants is not supported.
    $TenantFilter = [string]($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    # The user whose sign-ins to explain: UPN or Entra object ID. Required unless correlationId is given.
    $UserPrincipalName = [string]($Request.Query.userPrincipalName ?? $Request.Body.userPrincipalName.value ?? $Request.Body.userPrincipalName)
    # Hours to look back from now, 1 to 720. Defaults to 24. Ignored with correlationId.
    $HoursIn = $Request.Query.hours ?? $Request.Body.hours
    # A sign-in correlation ID or request ID (GUID), from the user's error screen or a ticket. Searches the last 30 days.
    $CorrelationId = [string]($Request.Query.correlationId ?? $Request.Body.correlationId)
    # true to include non-interactive sign-ins (apps refreshing tokens in the background). Defaults to false.
    $IncludeNonInteractive = ConvertTo-CIPPBoolean -Value ($Request.Query.includeNonInteractive ?? $Request.Body.includeNonInteractive ?? $false)
    # How many failed or interrupted sign-ins to explain in full, 1 to 100, newest first. Defaults to 25.
    $MaxIn = $Request.Query.maxResults ?? $Request.Body.maxResults

    $Bad = { param($Message) [HttpResponseContext]@{ StatusCode = [System.Net.HttpStatusCode]::BadRequest; Body = @{ Results = $Message } } }
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') { return (& $Bad 'Select a single tenant: sign-ins are read live per tenant.') }
    if (-not $UserPrincipalName.Trim() -and -not $CorrelationId.Trim()) { return (& $Bad 'Give userPrincipalName, or correlationId.') }
    $Guid = [guid]::Empty
    if ($CorrelationId.Trim() -and -not [guid]::TryParse($CorrelationId.Trim(), [ref]$Guid)) { return (& $Bad "'$CorrelationId' is not a correlation ID or request ID (expected a GUID).") }
    $Hours = 24
    if ($HoursIn -as [int]) { $Hours = [math]::Min(720, [math]::Max(1, [int]$HoursIn)) }
    $MaxResults = 25
    if ($MaxIn -as [int]) { $MaxResults = [math]::Min(100, [math]::Max(1, [int]$MaxIn)) }

    try {
        $Params = @{ TenantFilter = $TenantFilter; Hours = $Hours; MaxResults = $MaxResults; IncludeNonInteractive = $IncludeNonInteractive }
        if ($UserPrincipalName.Trim()) { $Params.UserPrincipalName = $UserPrincipalName.Trim() }
        if ($CorrelationId.Trim()) { $Params.CorrelationId = $CorrelationId.Trim() }
        $Body = Get-CIPPSignInExplanation @Params
        $StatusCode = [System.Net.HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed to explain sign-ins: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [System.Net.HttpStatusCode]::InternalServerError
        $Body = @{ Results = "Failed to explain sign-ins: $($ErrorMessage.NormalizedError)" }
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Body
        })
}
