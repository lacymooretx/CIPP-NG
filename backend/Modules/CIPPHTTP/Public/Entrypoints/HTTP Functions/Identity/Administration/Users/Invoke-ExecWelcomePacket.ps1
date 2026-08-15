Function Invoke-ExecWelcomePacket {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.ReadWrite
    .DESCRIPTION
        Builds the printable new-hire welcome packet for a single user: identity from
        Graph, brand and support details from the tenant's welcome packet config, and
        the live password read back from IT Glue.

        Read-only by design. This endpoint never resets a password, even though it
        returns one. Resetting lives in ExecResetPass, which already generates,
        delivers and documents the credential under one audit trail; a second reset
        path here would be a second way for plaintext to escape and a second thing to
        keep correct. The frontend gets a fresh password by calling ExecResetPass with
        DocumentInITGlue enabled and then re-reading this endpoint.

        ReadWrite rather than Read: the response carries a live credential. Read
        access to a user should not be enough to print their password.

        Aspendora fork addition.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $StatusCode = [HttpStatusCode]::OK

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    $UserId = $Request.Query.UserID ?? $Request.Body.UserID

    try {
        if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($UserId)) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{'Results' = 'Both tenantFilter and UserID are required.' }
                })
        }

        $User = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($UserId)?`$select=id,displayName,givenName,userPrincipalName,mail,jobTitle,department" -tenantid $TenantFilter -noPagination $true

        if (-not $User) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::NotFound
                    Body       = @{'Results' = "No user found for '$UserId'." }
                })
        }

        # Every call hands an operator a live credential, so every call is logged with
        # who asked for it -- the same reason the reset path logs at Warning.
        Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message "Welcome packet requested for $($User.userPrincipalName)" -Sev 'Warning'

        $Branding = Get-CIPPWelcomePacketBranding -TenantFilter $TenantFilter

        $Packet = [ordered]@{
            user         = [ordered]@{
                displayName       = $User.displayName
                firstName         = Get-CIPPWelcomePacketFirstName -User $User
                userPrincipalName = $User.userPrincipalName
                email             = if ([string]::IsNullOrWhiteSpace($User.mail)) { $User.userPrincipalName } else { $User.mail }
                jobTitle          = $User.jobTitle
                department        = $User.department
                password          = $null
            }
            company      = $Branding.company
            brand        = $Branding.brand
            support      = $Branding.support
            apps         = $Branding.apps
            signInUrl    = $Branding.signInUrl
            # US Central, not the container's UTC. The container runs in UTC, so
            # after 19:00 CDT Get-Date rolls to tomorrow and the sheet handed to
            # someone on a Thursday afternoon is dated Friday.
            preparedDate = (Get-CIPPWelcomePacketDate).ToString('d MMMM yyyy')

            # Everything below is for the operator, not the sheet.
            source       = 'none'
            itGlueUrl    = $null
            itGlueName   = $null
            isPortalRecord   = $false
            passwordUpdatedAtUtc = $null
            warning      = $null
        }

        $Stored = Get-ITGluePassword -TenantFilter $TenantFilter -UserPrincipalName $User.userPrincipalName

        $Packet.itGlueUrl = $Stored.Url
        $Packet.itGlueName = $Stored.Name
        $Packet.isPortalRecord = $Stored.IsPortalRecord
        $Packet.passwordUpdatedAtUtc = $Stored.UpdatedAtUtc

        if ($Stored.Success) {
            $Packet.user.password = $Stored.Password
            $Packet.source = 'ITGlue'
            # Success can still carry advice -- a username-matched or duplicated record.
            $Packet.warning = $Stored.Message
        } else {
            # No password is not an error. The sheet cannot print, but the operator gets
            # the packet, the reason, and a working 'generate a new password' button.
            $Packet.warning = $Stored.Message
        }

        $Results = [PSCustomObject]$Packet
    } catch {
        $ErrorMessage = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        Write-LogMessage -API $APIName -tenant $TenantFilter -headers $Headers -message "Welcome packet failed for $($UserId): $ErrorMessage" -Sev 'Error'
        $StatusCode = [HttpStatusCode]::InternalServerError
        $Results = "Failed to build the welcome packet: $ErrorMessage"
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @{'Results' = $Results }
        })
}
