function Invoke-ExecCAPreflight {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.ConditionalAccess.Read
    .SYNOPSIS
        Pre-flight a Conditional Access policy before it is turned On: break-glass exclusion, Global Admin access, What-If and report-only soak
    .DESCRIPTION
        Read-only; changes nothing in the tenant. POST (or GET) with tenantFilter and one of:
          PolicyId    an existing policy (evaluated as if switched to On)
          TemplateId  a CA template GUID
          Policy      the policy JSON (object or string) as it would be written
        Optional: Days (report-only days required, default 7, 1-30), SkipSignIns=true.
        Returns { Results = { Passed; Status; PolicyName; PolicyId; CurrentState; Checks[]; WhatIf[]; ReportOnly;
        WouldBeBlocked; Errors[]; CheckedUtc } }. Each check: { Key; Check; Status (Pass|Warn|Fail|Info); Message; Fix }.
        The same check gates AddCAPolicy, EditCAPolicy and ExecEditCAPolicyFull when they set a policy to On.
        Aspendora fork addition (Vikunja CIPP-5).
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = [string]($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $PolicyId = [string]($Request.Body.PolicyId ?? $Request.Query.PolicyId ?? $Request.Body.GUID ?? $Request.Query.GUID)
    $TemplateId = [string]($Request.Body.TemplateId ?? $Request.Query.TemplateId)
    $Policy = $Request.Body.Policy ?? $Request.Body.RawJSON
    $DaysRaw = $Request.Body.Days ?? $Request.Query.Days ?? 7
    $SkipSignIns = $Request.Body.SkipSignIns -eq $true -or $Request.Query.SkipSignIns -eq $true

    $Respond = { param($Code, $Body) [HttpResponseContext]@{ StatusCode = $Code; Body = $Body } }
    if (-not $TenantFilter -or $TenantFilter -eq 'AllTenants') { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'tenantFilter (a single tenant) is required.' }) }
    if (-not $PolicyId -and -not $TemplateId -and -not $Policy) { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'Give PolicyId, TemplateId or Policy.' }) }
    $Days = 0
    if (-not [int]::TryParse([string]$DaysRaw, [ref]$Days) -or $Days -lt 1 -or $Days -gt 30) { return (& $Respond ([HttpStatusCode]::BadRequest) @{ Results = 'Days must be a whole number from 1 to 30.' }) }

    try {
        $Params = @{ TenantFilter = $TenantFilter; Headers = $Headers; RequiredDays = $Days; SkipSignIns = $SkipSignIns }
        if ($PolicyId) { $Params.PolicyId = $PolicyId } elseif ($TemplateId) { $Params.TemplateId = $TemplateId } else { $Params.Policy = $Policy }
        $Result = Invoke-CIPPCAPreflight @Params
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "CA pre-flight for '$($Result.PolicyName)': $($Result.Status)" -Sev 'Info'
        return (& $Respond ([HttpStatusCode]::OK) @{ Results = $Result })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Message = "CA pre-flight failed to run: $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Message -Sev 'Error' -LogData $ErrorMessage
        return (& $Respond ([HttpStatusCode]::InternalServerError) @{ Results = $Message })
    }
}
