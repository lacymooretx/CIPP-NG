function Send-CIPPPasswordDelivery {
    <#
    .SYNOPSIS
    Delivers a newly set password to the people who need it, and documents it.

    .DESCRIPTION
    One entry point for everything that happens to a password after it has been set:
    push it to Password Pusher, have Password Pusher email and/or text the secret link
    to the user and optionally their supervisor, and write the password into the
    tenant's mapped IT Glue organization.

    Every step is independently fault tolerant. A failed text must not lose the
    password, and an unmapped IT Glue organization must not fail the reset -- each
    failure is reported back in the result and logged, and the caller still gets the
    password or link to hand over manually.

    Aspendora fork addition.

    .PARAMETER TenantFilter
    The tenant the user belongs to.

    .PARAMETER UserPrincipalName
    The user's UPN.

    .PARAMETER Password
    The password that was just set.

    .PARAMETER UserId
    Graph object id, used to look up mobile number and manager. Falls back to the UPN.

    .PARAMETER DisplayName
    The user's display name, for the push label and the IT Glue record.

    .PARAMETER RecipientEmail
    Where to email the user's copy of the link. When supplied this is the definitive list
    and no lookup happens. When omitted, the link goes to the user's primary address AND
    every alternate address on the Entra account (otherMails), since a user who needs a
    password reset may not be able to sign in to read the primary mailbox.

    .PARAMETER RecipientPhone
    Mobile number for the user's SMS copy. Read from Graph (mobilePhone) when omitted.

    .PARAMETER SupervisorEmail
    Supervisor email. Read from the Graph manager relationship when omitted.

    .PARAMETER SupervisorPhone
    Supervisor mobile. Read from the Graph manager relationship when omitted.

    .PARAMETER EmailUser
    Email the link to the user.

    .PARAMETER TextUser
    Text the link to the user.

    .PARAMETER NotifySupervisor
    Send the same link to the user's supervisor, by email and text where available.

    .PARAMETER DocumentInITGlue
    Write the password into the mapped IT Glue organization.

    .PARAMETER Reason
    Short description of what produced this password, recorded in IT Glue and used as
    the push label.
    #>
    [CmdletBinding()]
    # The password arrives as plaintext because that is what this function exists to move:
    # Graph has just generated or reset it, and it has to reach Password Pusher and IT Glue
    # over HTTPS as a string. A SecureString parameter would be decoded back to plaintext on
    # the first line and would advertise a protection that is not there.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'UserPrincipalName/Password are a freshly issued credential being handed to the delivery channels, not an interactive logon prompt; the value must stay plaintext to reach the pwpush and IT Glue APIs')]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$Password,

        [string]$UserId,

        [string]$DisplayName,

        [string[]]$RecipientEmail,

        [string]$RecipientPhone,

        [string]$SupervisorEmail,

        [string]$SupervisorPhone,

        [bool]$EmailUser = $true,

        [bool]$TextUser = $true,

        [bool]$NotifySupervisor = $false,

        [bool]$DocumentInITGlue = $true,

        [string]$Reason = 'Password reset',

        $Headers
    )

    $APIName = 'PasswordDelivery'
    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Notices = [System.Collections.Generic.List[string]]::new()

    if ([string]::IsNullOrWhiteSpace($DisplayName)) { $DisplayName = $UserPrincipalName }
    $Lookup = if (![string]::IsNullOrWhiteSpace($UserId)) { $UserId } else { $UserPrincipalName }

    # --- fill in whatever the caller did not supply, from Graph -------------------
    $RecipientEmail = @($RecipientEmail | Where-Object { ![string]::IsNullOrWhiteSpace($_) })
    $NeedsUser = ($EmailUser -and $RecipientEmail.Count -eq 0) -or
                 ($TextUser -and [string]::IsNullOrWhiteSpace($RecipientPhone))

    if ($NeedsUser) {
        try {
            $GraphUser = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($Lookup)?`$select=id,displayName,userPrincipalName,mail,mobilePhone,otherMails" -tenantid $TenantFilter -noPagination $true
            if ($TextUser -and [string]::IsNullOrWhiteSpace($RecipientPhone)) { $RecipientPhone = $GraphUser.mobilePhone }
            if ($EmailUser -and $RecipientEmail.Count -eq 0) {
                # Primary first, then every alternate. The primary may be unreadable to a
                # user who cannot sign in, so the alternates are what make this reliable.
                $Addresses = [System.Collections.Generic.List[string]]::new()
                $Primary = if (![string]::IsNullOrWhiteSpace($GraphUser.mail)) { $GraphUser.mail } else { $GraphUser.userPrincipalName }
                if (![string]::IsNullOrWhiteSpace($Primary)) { $Addresses.Add($Primary) }
                foreach ($Other in @($GraphUser.otherMails)) {
                    if (![string]::IsNullOrWhiteSpace($Other)) { $Addresses.Add($Other) }
                }
                $RecipientEmail = @($Addresses | Select-Object -Unique)
            }
        } catch {
            $Warnings.Add("Could not read the user's contact details from Graph: $($_.Exception.Message)")
        }
    }

    if ($NotifySupervisor -and [string]::IsNullOrWhiteSpace($SupervisorEmail) -and [string]::IsNullOrWhiteSpace($SupervisorPhone)) {
        try {
            $Manager = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($Lookup)/manager?`$select=displayName,mail,userPrincipalName,mobilePhone" -tenantid $TenantFilter -noPagination $true
            if ($Manager) {
                $SupervisorEmail = if ($Manager.mail) { $Manager.mail } else { $Manager.userPrincipalName }
                $SupervisorPhone = $Manager.mobilePhone
            }
        } catch {
            # Graph returns 404 when no manager is assigned, which is not an error worth logging as one.
            $Warnings.Add('No supervisor was found for this user, so no supervisor copy was sent. Set a manager in Entra, or enter one manually.')
        }
    }

    if ($EmailUser -and $RecipientEmail.Count -eq 0) {
        $Warnings.Add("No email address could be resolved for $UserPrincipalName, so the link was not emailed to them.")
    } elseif ($EmailUser -and $RecipientEmail.Count -eq 1) {
        $Notices.Add('Only the primary mailbox is on file - add an alternate address in Entra so a locked-out user can still receive the link.')
    }
    if ($TextUser -and [string]::IsNullOrWhiteSpace($RecipientPhone)) {
        $Warnings.Add("No mobile number is on file for $UserPrincipalName, so the link was not texted to them.")
    }
    if ($NotifySupervisor -and [string]::IsNullOrWhiteSpace($SupervisorEmail) -and [string]::IsNullOrWhiteSpace($SupervisorPhone)) {
        $Warnings.Add('No supervisor contact details were available, so no supervisor copy was sent.')
    }

    # --- create the push and dispatch it -----------------------------------------
    $Emails = @()
    if ($EmailUser) { $Emails += @($RecipientEmail) }
    $Phones = @()
    if ($TextUser -and ![string]::IsNullOrWhiteSpace($RecipientPhone)) { $Phones += $RecipientPhone }

    $PushParams = @{
        Payload = $Password
        Name    = "$Reason - $UserPrincipalName"
    }
    if ($Emails.Count -gt 0) { $PushParams['Emails'] = $Emails }
    if ($Phones.Count -gt 0) { $PushParams['Phones'] = $Phones }
    if ($NotifySupervisor) {
        if (![string]::IsNullOrWhiteSpace($SupervisorEmail)) { $PushParams['SupervisorEmail'] = $SupervisorEmail }
        if (![string]::IsNullOrWhiteSpace($SupervisorPhone)) { $PushParams['SupervisorPhone'] = $SupervisorPhone }
    }

    $Push = New-PwPushSecret @PushParams

    $Link = $null
    $Deliveries = @()
    if ($Push -and $Push.Success) {
        $Link = $Push.Link
        foreach ($PushError in $Push.Errors) { $Warnings.Add("Password Pusher refused a delivery: $PushError") }

        if ($Push.Dispatched) {
            $Deliveries = Get-PwPushDispatchStatus -UrlToken $Push.UrlToken
            if (-not $Deliveries -or $Deliveries.Count -eq 0) { $Deliveries = $Push.Deliveries }

            foreach ($Delivery in $Deliveries) {
                if ($Delivery.status -eq 'failed') {
                    $Warnings.Add("Delivery failed - $($Delivery.channel) to the $($Delivery.role) at $($Delivery.destination): $($Delivery.error)")
                } elseif ($Delivery.status -eq 'sent') {
                    $Notices.Add("Sent by $($Delivery.channel) to the $($Delivery.role) at $($Delivery.destination).")
                } else {
                    $Notices.Add("Queued - $($Delivery.channel) to the $($Delivery.role) at $($Delivery.destination) had not left the queue yet.")
                }
            }
        }
    } elseif ($Push) {
        foreach ($PushError in $Push.Errors) { $Warnings.Add($PushError) }
    }

    # --- document it --------------------------------------------------------------
    $ITGlue = $null
    if ($DocumentInITGlue) {
        # A direct API client authenticates as a bare app id, which is useless in a
        # documentation note. Resolve it to the client's name, the same way access
        # checks distinguish an interactive user from an API client.
        $Actor = $Headers.'x-ms-client-principal-name'
        if ($Headers.'x-ms-client-principal-idp' -eq 'aad' -and $Actor -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            try {
                $Client = Get-CippApiClient -AppId $Actor
                $Actor = if ($Client.AppName) { "$($Client.AppName) (API client)" } else { "API client $Actor" }
            } catch {
                $Actor = "API client $Actor"
            }
        }
        if ([string]::IsNullOrWhiteSpace($Actor)) { $Actor = 'CIPP' }
        $Note = @(
            "Managed by CIPP - do not edit by hand; the next reset overwrites this record."
            "$Reason on $(Get-Date -Format 'yyyy-MM-dd HH:mm') UTC by $Actor."
            'This is the temporary password that was set. If the user was required to change it at next sign-in, this value is stale as soon as they do.'
        ) -join "`n"

        $ITGlue = Set-ITGluePassword -TenantFilter $TenantFilter -UserPrincipalName $UserPrincipalName -Password $Password -DisplayName $DisplayName -Notes $Note
        if ($ITGlue.Success) {
            $Notices.Add("IT Glue record $($ITGlue.Action).")
        } else {
            $Warnings.Add($ITGlue.Message)
        }
    }

    $Summary = @()
    $Summary += $Notices
    $Summary += $Warnings

    return [PSCustomObject]@{
        Link         = $Link
        UrlToken     = if ($Push) { $Push.UrlToken } else { $null }
        Dispatched   = if ($Push) { [bool]$Push.Dispatched } else { $false }
        Deliveries   = $Deliveries
        ITGlue       = $ITGlue
        Notices      = @($Notices)
        Warnings     = @($Warnings)
        Summary      = ($Summary -join ' ')
    }
}
