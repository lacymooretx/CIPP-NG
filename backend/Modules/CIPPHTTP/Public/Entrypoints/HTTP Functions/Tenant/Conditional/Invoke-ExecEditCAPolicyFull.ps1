function Invoke-ExecEditCAPolicyFull {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.ConditionalAccess.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter

    if ([string]::IsNullOrWhiteSpace($TenantFilter)) {
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ Results = 'Error: tenantFilter is required' }
        }
    }

    $PolicyId = $Request.Query.PolicyId ?? $Request.Body.PolicyId
    if ([string]::IsNullOrWhiteSpace($PolicyId)) {
        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ Results = 'Error: PolicyId is required' }
        }
    }

    try {
        $PolicyBody = $Request.Body.PolicyBody
        if ($null -eq $PolicyBody) {
            return [HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Error: PolicyBody is required' }
            }
        }

        # Strip read-only properties that cannot be PATCHed
        $CleanBody = $PolicyBody | Select-Object -Property * -ExcludeProperty id, createdDateTime, modifiedDateTime, templateId
        # Round-trip so the canonicalizer always sees a PSCustomObject, whatever shape the request
        # body deserialised into, then apply the same rules the template deploy path uses: managed
        # keys the body omits are restored as their cleared form (that is how a PATCH clears an
        # assignment) and a condition block Graph would reject half-populated becomes null instead.
        $PolicyObject = ConvertTo-Json -InputObject $CleanBody -Depth 20 | ConvertFrom-Json
        Format-CIPPCAPolicy -Policy $PolicyObject
        $RawJSON = ConvertTo-Json -InputObject $PolicyObject -Depth 20 -Compress

        # Aspendora fork addition (Vikunja CIPP-5): a save that leaves the policy On (state set to enabled, or
        # omitted on an already-enabled policy - an edit of an enforced policy, the 2026-10-07 class of mistake)
        # must pass the lockout pre-flight unless the operator ticked the override.
        $PreflightOverride = $Request.Body.PreflightOverride -eq $true
        $ExistingPolicy = $null
        $TargetState = $PolicyObject.state
        if (-not $TargetState) {
            $ExistingPolicy = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$PolicyId" -tenantid $TenantFilter -ErrorAction Stop
            $TargetState = $ExistingPolicy.state
        }
        if ($TargetState -eq 'enabled') {
            $Gate = $null
            try {
                $Preflight = Invoke-CIPPCAPreflight -TenantFilter $TenantFilter -PolicyId $PolicyId -Policy $PolicyObject -ExistingPolicy $ExistingPolicy -Headers $Headers
                $Gate = Resolve-CIPPCAPreflightGate -Result $Preflight -Mode 'Enforce' -Override $PreflightOverride -Headers $Headers -APIName $APIName -TenantFilter $TenantFilter
            } catch {
                $PreflightError = (Get-CippException -Exception $_).NormalizedError
                if (-not $PreflightOverride) {
                    $Blocked = "Blocked: the CA pre-flight check could not run for policy $PolicyId ($PreflightError). Re-submit with the pre-flight override ticked to proceed; the override is logged."
                    Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message $Blocked -sev Warning
                    return [HttpResponseContext]@{ StatusCode = [HttpStatusCode]::Conflict; Body = @{ Results = $Blocked } }
                }
                Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message "CA pre-flight could not run for policy $PolicyId ($PreflightError); saving because the override was ticked." -sev Warning
            }
            if ($Gate -and -not $Gate.Allowed) {
                Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message $Gate.Message -sev Warning
                return [HttpResponseContext]@{ StatusCode = [HttpStatusCode]::Conflict; Body = @{ Results = $Gate.Message; Preflight = $Gate.Preflight } }
            }
        }

        $null = New-GraphPOSTRequest `
            -uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$PolicyId" `
            -tenantid $TenantFilter `
            -type PATCH `
            -body $RawJSON `
            -asApp $true

        $DisplayName = $PolicyBody.displayName ?? $PolicyId
        $Result = "Successfully updated CA policy '$DisplayName' for $TenantFilter"
        Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message $Result -sev Info
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to update CA policy $PolicyId for ${TenantFilter}: $($ErrorMessage.NormalizedError)"
        Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message $Result -sev Error -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return [HttpResponseContext]@{
        StatusCode = $StatusCode ?? [HttpStatusCode]::OK
        Body       = @{ Results = $Result }
    }
}
