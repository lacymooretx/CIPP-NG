function Send-CIPPWelcomeEmail {
    <#
    .SYNOPSIS
    Sends a new hire the warm introduction that goes with the printed packet.

    .DESCRIPTION
    The companion to the welcome packet: who we are, where to sign in, what the
    first fifteen minutes look like, and how to get help. Sent to an address the
    new hire can actually read on day one — a personal address or their manager's
    — because the entire premise is that they cannot sign in yet.

    THIS EMAIL NEVER CARRIES THE PASSWORD. There is no parameter for one and no
    placeholder for one. The credential travels exactly one of two ways: printed
    on the sheet, or a Password Pusher secret link sent separately by
    Send-CIPPPasswordDelivery. A message holding both the username and the
    password is one interception away from an account takeover, and it sits in a
    mailbox forever. If someone asks for the password to be included "just for
    small clients", the answer is the Password Pusher link.

    Transport is Send-CIPPAlert -Type email -altEmail, which already posts to
    /me/sendMail on the partner tenant with the SAM app identity. Reused rather
    than reimplemented: a second mail path would be a second thing to keep
    authenticated, and the mail correctly comes from us rather than from the
    client's own tenant.

    The markup mirrors aspendora-branding/templates/welcome-email.html. That file
    is the master; when the copy changes, change it there and bring it across.

    Aspendora fork addition.

    .PARAMETER TenantFilter
    Tenant the user belongs to.

    .PARAMETER UserId
    Graph object id or UPN of the new hire.

    .PARAMETER RecipientEmail
    Where to send it. Required, and deliberately not defaulted to the user's own
    new mailbox — that is the one address they may not be able to open yet.

    .PARAMETER Delivery
    'printed' (default) when the password is on a sheet they will be handed, or
    'secureLink' when Password Pusher is sending it separately. Changes one
    paragraph so the reader is told where to actually look.

    .PARAMETER Headers
    Request headers, for attributing the send in the log.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter,

        [Parameter(Mandatory)]
        [string]$UserId,

        [Parameter(Mandatory)]
        [string]$RecipientEmail,

        [ValidateSet('printed', 'secureLink')]
        [string]$Delivery = 'printed',

        $Headers
    )

    $Result = [PSCustomObject]@{
        Success   = $false
        Recipient = $RecipientEmail
        Subject   = $null
        Message   = $null
    }

    try {
        if ($RecipientEmail -notlike '*@*') {
            $Result.Message = "'$RecipientEmail' is not an email address."
            return $Result
        }

        $User = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($UserId)?`$select=id,displayName,givenName,userPrincipalName,mail" -tenantid $TenantFilter -noPagination $true
        if (-not $User) {
            $Result.Message = "No user found for '$UserId'."
            return $Result
        }

        $Branding = Get-CIPPWelcomePacketBranding -TenantFilter $TenantFilter
        $FirstName = Get-CIPPWelcomePacketFirstName -User $User
        $Email = if ([string]::IsNullOrWhiteSpace($User.mail)) { $User.userPrincipalName } else { $User.mail }
        $Subject = "Welcome to $($Branding.company.name)"
        $Result.Subject = $Subject

        $PasswordLine = if ($Delivery -eq 'secureLink') {
            'You will get a second message with a secure, one-time link to it. That link expires, so open it when you are ready to sign in. We never put a password in the body of an email.'
        } else {
            'It is printed on the welcome sheet you will be handed on your first day. We never send a password by email.'
        }

        $LogoBlock = if ([string]::IsNullOrWhiteSpace($Branding.brand.logoUrl)) {
            "<div style=`"font-size:20px; font-weight:800; letter-spacing:-0.02em; color:#0f172a;`">$([System.Net.WebUtility]::HtmlEncode($Branding.brand.name))</div>"
        } else {
            # A same-origin path is meaningless in a mail client, so only an
            # absolute URL or a data URI is worth emitting here.
            $Logo = $Branding.brand.logoUrl
            if ($Logo -match '^(https?:|data:)') {
                "<img src=`"$Logo`" alt=`"$([System.Net.WebUtility]::HtmlEncode($Branding.brand.name))`" width=`"150`" style=`"width:150px; height:auto; border:0; display:block;`">"
            } else {
                "<div style=`"font-size:20px; font-weight:800; letter-spacing:-0.02em; color:#0f172a;`">$([System.Net.WebUtility]::HtmlEncode($Branding.brand.name))</div>"
            }
        }

        $Phone = if ([string]::IsNullOrWhiteSpace($Branding.support.phone)) { '' } else { " or call <strong style=`"color:#0f172a;`">$([System.Net.WebUtility]::HtmlEncode($Branding.support.phone))</strong>" }
        $Portal = if ([string]::IsNullOrWhiteSpace($Branding.support.portalUrl)) { '' } else { " You can also track a request at <strong style=`"color:#0f172a;`">$([System.Net.WebUtility]::HtmlEncode($Branding.support.portalUrl))</strong>." }

        $E = { param($t) [System.Net.WebUtility]::HtmlEncode($t) }
        $Step = {
            param($n, $Html)
            @"
        <tr>
          <td width="34" valign="top" style="padding:0 0 12px 0;">
            <div style="width:24px; height:24px; border-radius:12px; background:#2563eb; color:#ffffff; font-size:13px; font-weight:700; text-align:center; line-height:24px;">$n</div>
          </td>
          <td valign="top" style="padding:0 0 12px 0;">$Html</td>
        </tr>
"@
        }

        $Body = @"
<html><body style="margin:0; padding:0; background:#e2e8f0;">
<div style="display:none; max-height:0; overflow:hidden; opacity:0;">Your $(& $E $Branding.company.name) account is ready. Here is how to sign in on your first day.</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#e2e8f0; padding:24px 12px;">
<tr><td align="center">
  <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px; max-width:100%; background:#ffffff; border-radius:12px; overflow:hidden; font-family:'Plus Jakarta Sans', -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color:#0f1729;">
    <tr><td style="height:6px; background:#2563eb; line-height:6px; font-size:0;">&nbsp;</td></tr>
    <tr><td style="padding:28px 32px 0 32px;">$LogoBlock</td></tr>
    <tr><td style="padding:24px 32px 0 32px;">
      <h1 style="margin:0 0 12px 0; font-size:30px; line-height:1.1; font-weight:800; letter-spacing:-0.02em; color:#0f172a;">Welcome, $(& $E $FirstName).</h1>
      <p style="margin:0; font-size:16px; line-height:1.6; color:#475569;">Your $(& $E $Branding.company.name) account is set up and waiting for you. This note is everything you need to know before your first day — it takes two minutes to read.</p>
    </td></tr>
    <tr><td style="padding:24px 32px 0 32px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid #e2e8f0; border-radius:8px; overflow:hidden;">
        <tr><td style="background:#0f172a; color:#ffffff; font-size:11px; font-weight:700; letter-spacing:0.18em; text-transform:uppercase; padding:10px 16px;">Your account</td></tr>
        <tr><td style="padding:14px 16px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-size:15px;">
            <tr><td style="padding:5px 0; color:#475569; width:130px;">Sign in at</td><td style="padding:5px 0; font-weight:700; color:#0f172a;">$(& $E $Branding.signInUrl)</td></tr>
            <tr><td style="padding:5px 0; color:#475569;">Username</td><td style="padding:5px 0; font-weight:700; color:#0f172a; word-break:break-all;">$(& $E $User.userPrincipalName)</td></tr>
            <tr><td style="padding:5px 0; color:#475569;">Email address</td><td style="padding:5px 0; font-weight:700; color:#0f172a; word-break:break-all;">$(& $E $Email)</td></tr>
          </table>
        </td></tr>
      </table>
    </td></tr>
    <tr><td style="padding:20px 32px 0 32px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#eff6ff; border-left:4px solid #2563eb; border-radius:4px;">
        <tr><td style="padding:14px 18px; font-size:15px; line-height:1.6; color:#334155;"><strong style="color:#0f172a;">Your password comes separately.</strong> $PasswordLine</td></tr>
      </table>
    </td></tr>
    <tr><td style="padding:26px 32px 0 32px;">
      <h2 style="margin:0 0 6px 0; font-size:19px; font-weight:800; letter-spacing:-0.01em; color:#0f172a;">Your first 15 minutes</h2>
      <p style="margin:0 0 14px 0; font-size:15px; line-height:1.6; color:#475569;">Four steps, once, and you are set up for good.</p>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-size:15px; line-height:1.6; color:#334155;">
$(& $Step 1 "Go to <strong style=`"color:#0f172a;`">$(& $E $Branding.signInUrl)</strong> and sign in with your username above.")
$(& $Step 2 'Choose your own password. Four unrelated words beat a short one full of symbols.')
$(& $Step 3 'Install <strong style="color:#0f172a;">Microsoft Authenticator</strong> on your phone, then on your computer go to <strong style="color:#0f172a;">aka.ms/mfasetup</strong> and add it as a sign-in method. Your computer shows a QR code; you scan it with the app. This is required — it keeps your account safe even if your password is ever stolen.')
$(& $Step 4 'Open Outlook and Teams and sign in with the same details.')
      </table>
    </td></tr>
    <tr><td style="padding:12px 32px 0 32px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f1f5f9; border-radius:8px;">
        <tr><td style="padding:16px 18px; font-size:15px; line-height:1.6; color:#334155;"><strong style="color:#0f172a;">Stuck on any of it?</strong> That is what we are here for. Email <a href="mailto:$(& $E $Branding.support.email)" style="color:#2563eb; text-decoration:none; font-weight:700;">$(& $E $Branding.support.email)</a>$Phone.$Portal</td></tr>
      </table>
    </td></tr>
    <tr><td style="padding:18px 32px 0 32px;">
      <p style="margin:0; font-size:13px; line-height:1.6; color:#475569;"><strong style="color:#0f172a;">One security habit worth having from day one.</strong> Nobody from IT will ever ask you for your password. If an Authenticator notification appears when you were not signing in, tap <em>Deny</em> and tell us.</p>
    </td></tr>
    <tr><td style="padding:24px 32px 28px 32px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
        <tr><td style="border-top:1px solid #e2e8f0; padding-top:14px; font-size:12px; line-height:1.6; color:#64748b;">$(& $E $Branding.brand.name) — IT support for $(& $E $Branding.company.name)<br><a href="mailto:$(& $E $Branding.support.email)" style="color:#64748b; text-decoration:none;">$(& $E $Branding.support.email)</a></td></tr>
      </table>
    </td></tr>
  </table>
</td></tr>
</table>
</body></html>
"@

        # Belt and braces: the template has no password placeholder, but this is
        # the last point before the message leaves, and the cost of being wrong
        # is a credential in someone's mailbox forever.
        if ($Body -match 'password["'']?\s*[:=]\s*\S' -and $Body -notmatch 'Your password comes separately') {
            $Result.Message = 'Refusing to send: the rendered body looks like it contains a credential.'
            Write-LogMessage -API 'WelcomeEmail' -message "Refused to send the welcome email for $($User.userPrincipalName): body failed the credential check." -Sev 'Alert' -tenant $TenantFilter
            return $Result
        }

        if ($PSCmdlet.ShouldProcess($RecipientEmail, "Send welcome email for $($User.userPrincipalName)")) {
            $null = Send-CIPPAlert -Type 'email' -Title $Subject -HTMLContent $Body -altEmail $RecipientEmail -TenantFilter $TenantFilter -APIName 'Welcome Email'
        }

        $Result.Success = $true
        Write-LogMessage -API 'WelcomeEmail' -message "Sent the welcome email for $($User.userPrincipalName) to $RecipientEmail." -Sev 'Info' -tenant $TenantFilter -headers $Headers
        return $Result
    } catch {
        $ErrorMessage = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        $Result.Message = "Failed to send the welcome email: $ErrorMessage"
        Write-LogMessage -API 'WelcomeEmail' -message "Failed to send the welcome email for $($UserId): $ErrorMessage" -Sev 'Error' -tenant $TenantFilter -headers $Headers
        return $Result
    }
}
