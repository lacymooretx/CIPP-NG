function New-CIPPUser {
    [CmdletBinding()]
    param (
        $UserObj,
        $Aliases = 'Scheduled',
        $RestoreValues,
        $APIName = 'New User',
        $Headers
    )

    try {
        $UserObj = $UserObj | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10
        Write-Host $UserObj.PrimDomain.value
        $Aliases = ($UserObj.AddedAliases) -split '\s'
        $password = if ($UserObj.password) { $UserObj.password } else { New-passwordString }
        $UserPrincipalName = "$($UserObj.username)@$($UserObj.Domain ? $UserObj.Domain : $UserObj.PrimDomain.value)"
        Write-Host "Creating user $UserPrincipalName"
        Write-Host "tenant filter is $($UserObj.tenantFilter)"
        $normalizedOtherMails = @(
            @($UserObj.otherMails) | ForEach-Object {
                if ($null -ne $_) {
                    [string]$_ -split ','
                }
            } | ForEach-Object {
                $_.Trim()
            } | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            }
        )
        $BodyToship = [pscustomobject] @{
            'givenName'         = $UserObj.givenName
            'surname'           = $UserObj.surname
            'accountEnabled'    = $true
            'displayName'       = $UserObj.displayName
            'department'        = $UserObj.department
            'mailNickname'      = $UserObj.username ? $UserObj.username : $UserObj.mailNickname
            'userPrincipalName' = $UserPrincipalName
            'usageLocation'     = $UserObj.usageLocation.value ? $UserObj.usageLocation.value : $UserObj.usageLocation
            'otherMails'        = $normalizedOtherMails
            'jobTitle'          = $UserObj.jobTitle
            'mobilePhone'       = $UserObj.mobilePhone
            'streetAddress'     = $UserObj.streetAddress
            'city'              = $UserObj.city
            'state'             = $UserObj.state
            'country'           = $UserObj.country
            'postalCode'        = $UserObj.postalCode
            'companyName'       = $UserObj.companyName
            'passwordProfile'   = @{
                'forceChangePasswordNextSignIn' = [bool]$UserObj.MustChangePass
                'password'                      = $password
            }
        }
        if ($UserObj.businessPhones) { $bodytoShip | Add-Member -NotePropertyName businessPhones -NotePropertyValue @($UserObj.businessPhones) }
        if ($UserObj.defaultAttributes) {
            $UserObj.defaultAttributes | Get-Member -MemberType NoteProperty | ForEach-Object {
                Write-Host "Editing user and adding $($_.Name) with value $($UserObj.defaultAttributes.$($_.Name).value)"
                if (-not [string]::IsNullOrWhiteSpace($UserObj.defaultAttributes.$($_.Name).value)) {
                    Write-Host 'adding body to ship'
                    $BodyToShip | Add-Member -NotePropertyName $_.Name -NotePropertyValue $UserObj.defaultAttributes.$($_.Name).value -Force
                }
            }
        }
        if ($UserObj.customData) {
            $UserObj.customData | Get-Member -MemberType NoteProperty | ForEach-Object {
                Write-Host "Editing user and adding custom data $($_.Name) with value $($UserObj.customData.$($_.Name))"
                if (-not [string]::IsNullOrWhiteSpace($UserObj.customData.$($_.Name))) {
                    Write-Host 'adding custom data to body'
                    $BodyToShip | Add-Member -NotePropertyName $_.Name -NotePropertyValue $UserObj.customData.$($_.Name) -Force
                }
            }
        }
        $bodyToShip = ConvertTo-Json -Depth 10 -InputObject $BodyToship -Compress
        Write-Host "Shipping: $bodyToShip"
        $GraphRequest = New-GraphPostRequest -uri 'https://graph.microsoft.com/beta/users' -tenantId $UserObj.tenantFilter -type POST -body $BodyToship -verbose
        Write-LogMessage -headers $Headers -API $APIName -tenant $($UserObj.tenantFilter) -message "Created user $($UserObj.displayName) with id $($GraphRequest.id)" -Sev 'Info'

        # Aspendora fork: deliver the password to the user and their supervisor, and document it.
        $DeliveryResult = $null
        try {
            $Options = Get-CIPPPasswordDeliveryOptions -Delivery $UserObj.Delivery
            if ($Options.Enabled) {
                # Graph may not have the new mailbox addresses yet, so build the recipient
                # list from what was just submitted: primary UPN plus any alternates.
                $NewUserEmails = if (@($Options.RecipientEmail).Count -gt 0) {
                    @($Options.RecipientEmail)
                } else {
                    @(@($UserPrincipalName) + @($normalizedOtherMails) | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
                }
                # A brand new user has no manager relationship in Entra yet, so the
                # supervisor can only come from the form.
                $DeliveryResult = Send-CIPPPasswordDelivery -TenantFilter $UserObj.tenantFilter `
                    -UserPrincipalName $UserPrincipalName `
                    -Password $password `
                    -UserId $GraphRequest.id `
                    -DisplayName $UserObj.displayName `
                    -RecipientEmail $NewUserEmails `
                    -RecipientPhone ($Options.RecipientPhone ?? $UserObj.mobilePhone) `
                    -SupervisorEmail $Options.SupervisorEmail `
                    -SupervisorPhone $Options.SupervisorPhone `
                    -EmailUser $Options.EmailUser `
                    -TextUser $Options.TextUser `
                    -NotifySupervisor $Options.NotifySupervisor `
                    -DocumentInITGlue $Options.DocumentInITGlue `
                    -Reason 'New user created' `
                    -Headers $Headers

                if ($DeliveryResult.Link) { $password = $DeliveryResult.Link }
            } else {
                $PasswordLink = New-PwPushLink -Payload $password
                if ($PasswordLink) {
                    $password = $PasswordLink
                }
            }
        } catch {
            Write-LogMessage -headers $Headers -API $APIName -tenant $($UserObj.tenantFilter) -message "Created the user but could not deliver the password: $($_.Exception.Message)" -Sev 'Warning'
        }
        $Results = @{
            Results  = if ($DeliveryResult.Summary) { "Created New User. $($DeliveryResult.Summary)" } else { 'Created New User.' }
            Username = $UserPrincipalName
            Password = $password
            User     = $GraphRequest
            Delivery = $DeliveryResult
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Result = "Failed to create user. Error:$($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -tenant $($UserObj.tenantFilter) -message "Failed to create user. Error:$($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
        $Results = @{ Results = $Result }
        throw $Result
    }
    return $Results
}

