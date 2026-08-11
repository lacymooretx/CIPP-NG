function Set-CIPPResetPassword {
    [CmdletBinding()]
    param(
        $UserID,
        $DisplayName,
        $TenantFilter,
        $APIName = 'Reset Password',
        $Headers,
        [bool]$forceChangePasswordNextSignIn = $true,
        $Delivery
    )

    try {
        $password = New-passwordString

        $UserDetails = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($UserID)?`$select=onPremisesSyncEnabled,userPrincipalName,displayName,mobilePhone,otherMails" -noPagination $true -tenantid $TenantFilter -verbose
        $IsSynced = $UserDetails.onPremisesSyncEnabled -eq $true

        if ($IsSynced) {
            $ResetBody = @{ 'newPassword' = $password } | ConvertTo-Json -Compress
            $null = New-GraphPostRequest -uri "https://graph.microsoft.com/beta/users/$($UserID)/authentication/methods/28c10230-6103-485e-b985-444c60001490/resetPassword" -tenantid $TenantFilter -type POST -body $ResetBody -verbose
        } else {
            $passwordProfile = @{
                'passwordProfile' = @{
                    'forceChangePasswordNextSignIn' = $forceChangePasswordNextSignIn
                    'password'                      = $password
                }
            } | ConvertTo-Json -Compress

            $null = New-GraphPostRequest -uri "https://graph.microsoft.com/v1.0/users/$($UserID)" -tenantid $TenantFilter -type PATCH -body $passwordProfile -verbose
        }

        #PWPush - deliver the secret and document it (Aspendora fork)
        $DeliveryNote = ''
        try {
            $Options = Get-CIPPPasswordDeliveryOptions -Delivery $Delivery
            if ($Options.Enabled) {
                $DeliveryResult = Send-CIPPPasswordDelivery -TenantFilter $TenantFilter `
                    -UserPrincipalName $UserDetails.userPrincipalName `
                    -Password $password `
                    -UserId $UserID `
                    -DisplayName $DisplayName `
                    -RecipientEmail $Options.RecipientEmail `
                    -RecipientPhone $Options.RecipientPhone `
                    -SupervisorEmail $Options.SupervisorEmail `
                    -SupervisorPhone $Options.SupervisorPhone `
                    -EmailUser $Options.EmailUser `
                    -TextUser $Options.TextUser `
                    -NotifySupervisor $Options.NotifySupervisor `
                    -DocumentInITGlue $Options.DocumentInITGlue `
                    -Reason 'Password reset' `
                    -Headers $Headers

                if ($DeliveryResult.Link) { $password = $DeliveryResult.Link }
                if ($DeliveryResult.Summary) { $DeliveryNote = " $($DeliveryResult.Summary)" }
            } else {
                $PasswordLink = New-PwPushLink -Payload $password
                if ($PasswordLink -and $PasswordLink -ne $false) {
                    $password = $PasswordLink
                }
            }
        }
        catch {
            Write-LogMessage -headers $Headers -API $APIName -message "Failed to create PwPush link, using plain password. Error: $($_.Exception.Message)" -sev 'Warning' -tenant $TenantFilter
        }
        if ($IsSynced) {
            Write-LogMessage -headers $Headers -API $APIName -message "Submitted a password writeback reset for $DisplayName, $($UserID). This user is directory synced, so the reset was sent via password writeback and the user must change password at next logon regardless of the requested setting ($forceChangePasswordNextSignIn)." -Sev 'Info' -tenant $TenantFilter

            return [pscustomobject]@{
                resultText = "Password reset accepted for $DisplayName, $($UserID). The new password is $password.$DeliveryNote This user is directory synced, so the reset was submitted via password writeback and is applied asynchronously - it is not confirmed yet, and will fail if writeback is not enabled or if the on-premises password policy rejects the password. This user must change their password at next logon; that is enforced by this method and cannot be turned off."
                copyField  = $password
                state      = 'success'
            }
        } else {
            Write-LogMessage -headers $Headers -API $APIName -message "Successfully reset the password for $DisplayName, $($UserID). User must change password is set to $forceChangePasswordNextSignIn" -Sev 'Info' -tenant $TenantFilter

            return [pscustomobject]@{
                resultText = "Successfully reset the password for $DisplayName, $($UserID). User must change password is set to $forceChangePasswordNextSignIn. The new password is $password.$DeliveryNote"
                copyField  = $password
                state      = 'success'
            }
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $Message = "Failed to reset password for $DisplayName, $($UserID). Error: $($ErrorMessage.NormalizedError)"
        Write-LogMessage -headers $Headers -API $APIName -message $Message -Sev 'Error' -tenant $TenantFilter -LogData $ErrorMessage
        throw $Message
    }
}
