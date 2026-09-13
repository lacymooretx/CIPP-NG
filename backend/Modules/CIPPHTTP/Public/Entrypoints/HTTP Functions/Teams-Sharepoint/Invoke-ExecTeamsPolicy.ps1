function Invoke-ExecTeamsPolicy {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Teams.Config.ReadWrite
    .DESCRIPTION
        Creates, updates and removes Microsoft Teams admin policies for a tenant via the
        Teams ConfigAPI (New-TeamsRequestV2). The typed write counterpart of
        ListTeamsPolicy.

        Body params:
          TenantFilter (required) - tenant default domain or customer id
          PolicyType   (required) - ConfigAPI type, cmdlet noun, or full cmdlet name
                                    (e.g. 'TeamsMeetingPolicy')
          Action                  - Set (default) | New | Remove
          Identity                - policy instance. Default 'Global'. Custom instances are
                                    conventionally 'Tag:<Name>'
          Parameters              - object of properties to write. Required for Set/New.
                                    Set is a MERGE - only the properties you send change
          NoRead                  - true to skip the read-for-Key step and PUT bare props
          AsApp                   - true to use an application token instead of delegated

        Set applies to the whole tenant (Global) or to everyone the named policy is
        assigned to. Every call is audited. Per New-TeamsRequestV2's own notes, New and
        Remove are best-effort - not every ConfigAPI type supports creating named
        instances this way. Always read back after writing.

    .EXAMPLE
        POST /api/ExecTeamsPolicy
        { "TenantFilter": "contoso.com", "PolicyType": "TeamsMeetingPolicy",
          "Identity": "Global",
          "Parameters": { "AllowAnonymousUsersToJoinMeeting": false } }
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.TenantFilter ?? $Request.Query.TenantFilter ?? $Request.Query.tenantFilter
    $PolicyType = $Request.Body.PolicyType ?? $Request.Query.PolicyType
    $Action = $Request.Body.Action ?? $Request.Query.Action ?? 'Set'
    $Identity = $Request.Body.Identity ?? $Request.Query.Identity ?? 'Global'
    $Parameters = $Request.Body.Parameters

    $TruthyValues = @($true, 'true', 'True', 1, '1', 'yes', 'on')
    $NoRead = ($Request.Body.NoRead ?? $Request.Query.NoRead) -in $TruthyValues
    $AsApp = ($Request.Body.AsApp ?? $Request.Query.AsApp) -in $TruthyValues

    $ValidActions = @('Set', 'New', 'Remove')

    # ---- validation ----
    if (-not $TenantFilter) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = 'TenantFilter is required.' }
            })
    }
    if (-not $PolicyType) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = 'PolicyType is required.' }
            })
    }
    # Normalize case so callers can send 'set'/'SET' as well as 'Set'.
    $Action = ($ValidActions | Where-Object { $_ -eq $Action }) ?? $Action
    if ($Action -notin $ValidActions) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Invalid Action '$Action'. Allowed: $($ValidActions -join ', '). Use ListTeamsPolicy to read." }
            })
    }
    if ($Action -in @('Set', 'New') -and -not $Parameters) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Action '$Action' requires Parameters." }
            })
    }

    # JSON bodies deserialize to PSCustomObject; New-TeamsRequestV2 takes [hashtable].
    $ParamHash = $null
    if ($null -ne $Parameters) {
        if ($Parameters -is [hashtable]) {
            $ParamHash = $Parameters
        } else {
            $ParamHash = @{}
            foreach ($Prop in $Parameters.PSObject.Properties) { $ParamHash[$Prop.Name] = $Prop.Value }
        }
    }

    # Federation-backed types sit on the legacy OcsPowershellWebservice and need the
    # discovered host + target-uri headers.
    $FederationTypes = @('TenantFederationSettings', 'TenantFederationConfiguration', 'TeamsAcsFederationConfiguration')
    $NormalizedType = $PolicyType -replace '^(Get|Set|New|Remove|Grant|Revoke)-Cs', ''

    try {
        $Splat = @{
            TenantFilter = $TenantFilter
            Type         = $PolicyType
            Action       = $Action
            Identity     = $Identity
        }
        if ($ParamHash) { $Splat.Parameters = $ParamHash }
        if ($NoRead) { $Splat.NoRead = $true }
        if ($AsApp) { $Splat.AsApp = $true }
        if ($NormalizedType -in $FederationTypes) { $Splat.UseServiceDiscovery = $true }

        $Results = New-TeamsRequestV2 @Splat

        $ChangedProps = if ($ParamHash) { ($ParamHash.Keys | Sort-Object) -join ', ' } else { '' }
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Teams policy $Action on $NormalizedType/$Identity ($ChangedProps)" -Sev 'Info'

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = [pscustomobject]@{
                    Results = "Successfully applied $Action to $NormalizedType/$Identity."
                    Details = $Results
                }
            })
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Teams policy $Action failed on $NormalizedType/$Identity - $ErrorMessage" -Sev 'Error'
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = [pscustomobject]@{ Results = "Teams Error: $ErrorMessage - $Action $NormalizedType/$Identity" }
            })
    }
}
