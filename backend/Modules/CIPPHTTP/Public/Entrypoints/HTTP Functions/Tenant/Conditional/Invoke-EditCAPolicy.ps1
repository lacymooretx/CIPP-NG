Function Invoke-EditCAPolicy {
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


    # Interact with the request
    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    $ID = $Request.Query.GUID ?? $Request.Body.GUID
    $State = $Request.Query.State ?? $Request.Body.State
    $DisplayName = $Request.Query.newDisplayName ?? $Request.Body.newDisplayName
    $PreflightOverride = $Request.Body.PreflightOverride -eq $true -or $Request.Query.PreflightOverride -eq $true

    # Aspendora fork addition (Vikunja CIPP-5): turning a policy On must pass the lockout pre-flight unless overridden.
    if ($State -eq 'enabled') {
        try {
            $Preflight = Invoke-CIPPCAPreflight -TenantFilter $TenantFilter -PolicyId $ID -Headers $Headers
            $Gate = Resolve-CIPPCAPreflightGate -Result $Preflight -Mode 'Enforce' -Override $PreflightOverride -Headers $Headers -APIName $APIName -TenantFilter $TenantFilter
        } catch {
            $ErrorMessage = Get-CippException -Exception $_
            if (-not $PreflightOverride) {
                $Result = "Blocked: the CA pre-flight check could not run for policy $($ID) ($($ErrorMessage.NormalizedError)). Re-submit with the pre-flight override ticked to proceed; the override is logged."
                Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Result -Sev 'Warning' -LogData $ErrorMessage
                return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::Conflict; Body = @{ Results = $Result } })
            }
            Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "CA pre-flight could not run for policy $($ID) ($($ErrorMessage.NormalizedError)); enabling because the override was ticked." -Sev 'Warning'
            $Gate = $null
        }
        if ($Gate -and -not $Gate.Allowed) {
            Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message $Gate.Message -Sev 'Warning'
            return ([HttpResponseContext]@{ StatusCode = [HttpStatusCode]::Conflict; Body = @{ Results = $Gate.Message; Preflight = $Gate.Preflight } })
        }
    }

    try {
        $properties = @{}

        # Conditionally add properties
        if ($State) {
            $properties["state"] = $State
        }

        if ($DisplayName) {
            $properties["displayName"] = $DisplayName
        }

        $Request = New-GraphPOSTRequest -uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($ID)" -tenantid $TenantFilter -type PATCH -body ($properties | ConvertTo-Json) -asapp $true

        $Result = "Successfully updated CA policy $($ID)"
        if ($State) { $Result += " state to $($State)" }
        if ($DisplayName) { $Result += " name to '$($DisplayName)'" }

        Write-LogMessage -headers $Headers -API $APIName -tenant $($TenantFilter) -message $Result -Sev 'Info'
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to update CA policy $($ID): $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -tenant $($TenantFilter) -message $Result -Sev 'Error' -LogData $ErrorMessage
        $StatusCode = [HttpStatusCode]::InternalServerError
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{ 'Results' = $Result }
        })

}
