Function Invoke-ExecSendWelcomeEmail {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.ReadWrite
    .DESCRIPTION
        Sends the new-hire welcome email — the warm introduction that goes with the
        printed packet. Never carries the password; see Send-CIPPWelcomeEmail.

        The recipient is required and must be typed by the operator. It is
        deliberately not defaulted to the user's own mailbox: the whole premise is
        that the new hire cannot sign in yet, so it goes to a personal address or
        their manager.

        Aspendora fork addition.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $StatusCode = [HttpStatusCode]::OK

    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $UserId = $Request.Body.UserID ?? $Request.Query.UserID
    $Recipient = $Request.Body.RecipientEmail ?? $Request.Query.RecipientEmail
    $Delivery = $Request.Body.Delivery ?? $Request.Query.Delivery ?? 'printed'

    try {
        if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($UserId)) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{'Results' = 'Both tenantFilter and UserID are required.' }
                })
        }
        if ([string]::IsNullOrWhiteSpace($Recipient)) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{'Results' = 'RecipientEmail is required — send this to an address the new hire can actually read on day one.' }
                })
        }
        if ($Delivery -notin @('printed', 'secureLink')) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{'Results' = "Delivery must be 'printed' or 'secureLink'." }
                })
        }

        $Send = Send-CIPPWelcomeEmail -TenantFilter $TenantFilter -UserId $UserId -RecipientEmail $Recipient -Delivery $Delivery -Headers $Headers

        if ($Send.Success) {
            $Results = "Sent the welcome email to $($Send.Recipient)."
        } else {
            $StatusCode = [HttpStatusCode]::BadRequest
            $Results = $Send.Message ?? 'The welcome email could not be sent.'
        }
    } catch {
        $ErrorMessage = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message "Welcome email failed: $ErrorMessage" -Sev 'Error'
        $StatusCode = [HttpStatusCode]::InternalServerError
        $Results = "Failed to send the welcome email: $ErrorMessage"
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{'Results' = $Results }
        })
}
