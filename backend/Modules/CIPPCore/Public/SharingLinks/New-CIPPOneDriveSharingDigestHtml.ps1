function New-CIPPOneDriveSharingDigestHtml {
    <#
    .SYNOPSIS
        Renders one user's weekly OneDrive sharing digest as a branded HTML email.
    .DESCRIPTION
        Takes one entry of Get-CIPPOneDriveSharingDigest's Users and returns @{ Subject; Html }.
        Links that leave the organization come first, with edit and no-expiry flags; links inside the
        organization follow. Long lists are capped, with a pointer to OneDrive's own "Shared" view.

        The look follows the welcome email (Send-CIPPWelcomeEmail): table layout and inline styles,
        because Outlook ignores most CSS. The logo is a hosted PNG; mail clients block data URIs and SVG.

        Aspendora fork addition.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $User,
        [Parameter(Mandatory = $true)]
        [string]$CompanyName,
        [string]$SupportEmail = 'help@aspendora.com',
        [string]$SupportPhone = '281-941-4028',
        [string]$BrandName = 'Aspendora Technologies',
        [string]$LogoUrl = 'https://www.aspendora.com/wp-content/uploads/2022/10/aspendora-logo-148.png',
        [int]$MaxOutsideRows = 100,
        [int]$MaxInsideRows = 50
    )

    $E = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $Central = [TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago')
    $Outside = @($User.Outside)
    $Inside = @($User.Inside)
    $AnyoneEdit = @($Outside | Where-Object { $_.Anonymous -and $_.Access -eq 'Can edit' }).Count
    $NeverExpires = @($Outside | Where-Object { $_.Anonymous -and -not $_.Expires }).Count

    $Name = if ($User.GivenName) { $User.GivenName } else { $User.DisplayName }
    $SharedView = if ($User.DriveUrl -match '^(https://[^/]+)/') { "$($Matches[1])/my?v=shared" } else { $null }

    $Pill = {
        param($Text, $Bg, $Fg)
        "<span style=`"display:inline-block; margin:2px 4px 2px 0; padding:1px 8px; border-radius:10px; background:$Bg; color:$Fg; font-size:11px; font-weight:700; white-space:nowrap;`">$(& $E $Text)</span>"
    }

    $Who = {
        param($Row)
        if ($Row.Anonymous) { return 'Anyone who has the link' }
        if ($Row.Audience -eq 'Everyone in your organization') { return "Anyone at $CompanyName who has the link" }
        if (@($Row.Recipients).Count -gt 0) { return (@($Row.Recipients) -join ', ') }
        $Row.Audience
    }

    $Table = {
        param($Rows, [int]$Max)
        $Shown = @($Rows | Select-Object -First $Max)
        $Body = foreach ($Row in $Shown) {
            $Flags = [System.Collections.Generic.List[string]]::new()
            if ($Row.Anonymous -and $Row.Access -eq 'Can edit') { $Flags.Add((& $Pill 'Anyone can edit' '#fee2e2' '#b91c1c')) }
            if ($Row.Anonymous -and -not $Row.Expires) { $Flags.Add((& $Pill 'Never expires' '#fef3c7' '#92400e')) }
            if ($Row.ItemType -eq 'Folder') { $Flags.Add((& $Pill 'Whole folder' '#e0e7ff' '#3730a3')) }
            if ($Row.HasPassword) { $Flags.Add((& $Pill 'Password' '#dcfce7' '#166534')) }
            $Expires = if ($Row.Expires) { [TimeZoneInfo]::ConvertTime($Row.Expires, $Central).ToString('MMM d, yyyy') } else { 'Never' }
            $Item = if ($Row.Url) { "<a href=`"$(& $E $Row.Url)`" style=`"color:#2563eb; text-decoration:none; font-weight:700;`">$(& $E $Row.Name)</a>" } else { "<strong>$(& $E $Row.Name)</strong>" }
            @"
            <tr>
              <td style="padding:10px 12px; border-top:1px solid #e2e8f0; vertical-align:top; word-break:break-word;">$Item<br><span style="font-size:12px; color:#64748b;">$(& $E $Row.ItemType)</span> $($Flags -join '')</td>
              <td style="padding:10px 12px; border-top:1px solid #e2e8f0; vertical-align:top; word-break:break-word;">$(& $E (& $Who $Row))</td>
              <td style="padding:10px 12px; border-top:1px solid #e2e8f0; vertical-align:top; white-space:nowrap;">$(& $E $Row.Access)</td>
              <td style="padding:10px 12px; border-top:1px solid #e2e8f0; vertical-align:top; white-space:nowrap;">$(& $E $Expires)</td>
            </tr>
"@
        }
        $More = if ($Rows.Count -gt $Max) {
            $Link = if ($SharedView) { " See them all in <a href=`"$(& $E $SharedView)`" style=`"color:#2563eb;`">OneDrive &rsaquo; Shared</a>." } else { '' }
            "<tr><td colspan=`"4`" style=`"padding:10px 12px; border-top:1px solid #e2e8f0; font-size:13px; color:#475569;`">And $($Rows.Count - $Max) more.$Link</td></tr>"
        } else { '' }
        @"
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid #e2e8f0; border-radius:8px; font-size:14px; line-height:1.5; color:#334155;">
            <tr style="background:#f8fafc; font-size:11px; font-weight:700; letter-spacing:0.08em; text-transform:uppercase; color:#475569;">
              <td style="padding:8px 12px;">Item</td><td style="padding:8px 12px;">Who can open it</td><td style="padding:8px 12px;">Access</td><td style="padding:8px 12px;">Expires</td>
            </tr>
$($Body -join "`n")
$More
          </table>
"@
    }

    $Section = {
        param($Title, $Intro, $Rows, [int]$Max)
        if ($Rows.Count -eq 0) { return '' }
        @"
    <tr><td style="padding:26px 32px 0 32px;">
      <h2 style="margin:0 0 6px 0; font-size:18px; font-weight:800; color:#0f172a;">$(& $E $Title) ($($Rows.Count))</h2>
      <p style="margin:0 0 12px 0; font-size:14px; line-height:1.6; color:#475569;">$Intro</p>
$(& $Table $Rows $Max)
    </td></tr>
"@
    }

    $Alert = if ($AnyoneEdit -gt 0 -or $NeverExpires -gt 0) {
        $Parts = @()
        if ($AnyoneEdit -gt 0) { $Parts += "$AnyoneEdit $(if ($AnyoneEdit -eq 1) { 'link lets' } else { 'links let' }) <strong>anyone</strong> with the link change your files" }
        if ($NeverExpires -gt 0) { $Parts += "$NeverExpires &ldquo;anyone&rdquo; $(if ($NeverExpires -eq 1) { 'link never expires' } else { 'links never expire' })" }
        @"
    <tr><td style="padding:20px 32px 0 32px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#fef2f2; border-left:4px solid #dc2626; border-radius:4px;">
        <tr><td style="padding:14px 18px; font-size:15px; line-height:1.6; color:#334155;"><strong style="color:#0f172a;">Worth a look:</strong> $($Parts -join '; '). If you no longer need them, please remove them.</td></tr>
      </table>
    </td></tr>
"@
    } else { '' }

    $Total = $Outside.Count + $Inside.Count
    $Subject = if ($Outside.Count -gt 0) {
        "Your OneDrive sharing: $($Outside.Count) $(if ($Outside.Count -eq 1) { 'link reaches' } else { 'links reach' }) outside $CompanyName"
    } else {
        "Your OneDrive sharing: $Total shared $(if ($Total -eq 1) { 'item' } else { 'items' })"
    }

    $Html = @"
<html><body style="margin:0; padding:0; background:#e2e8f0;">
<div style="display:none; max-height:0; overflow:hidden; opacity:0;">A weekly list of the files and folders you are sharing from OneDrive.</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#e2e8f0; padding:24px 12px;">
<tr><td align="center">
  <table role="presentation" width="680" cellpadding="0" cellspacing="0" border="0" style="width:680px; max-width:100%; background:#ffffff; border-radius:12px; overflow:hidden; font-family:'Plus Jakarta Sans', -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color:#0f1729;">
    <tr><td style="height:6px; background:#2563eb; line-height:6px; font-size:0;">&nbsp;</td></tr>
    <tr><td style="padding:28px 32px 0 32px;"><img src="$(& $E $LogoUrl)" alt="$(& $E $BrandName)" width="148" style="width:148px; height:auto; border:0; display:block;"></td></tr>
    <tr><td style="padding:24px 32px 0 32px;">
      <h1 style="margin:0 0 12px 0; font-size:26px; line-height:1.15; font-weight:800; letter-spacing:-0.02em; color:#0f172a;">Hi $(& $E $Name), here is what you are sharing.</h1>
      <p style="margin:0; font-size:15px; line-height:1.6; color:#475569;">These are the files and folders in your OneDrive that other people can open through a sharing link. Please take a minute to look over the list. If something no longer needs to be shared, stop sharing it. Fewer open links means less risk to $(& $E $CompanyName) if a link is ever forwarded or leaked.</p>
    </td></tr>
    <tr><td style="padding:20px 32px 0 32px;">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td style="padding:12px 18px; background:$(if ($Outside.Count -gt 0) { '#fef2f2' } else { '#f1f5f9' }); border-radius:8px; text-align:center;"><div style="font-size:26px; font-weight:800; color:$(if ($Outside.Count -gt 0) { '#b91c1c' } else { '#0f172a' });">$($Outside.Count)</div><div style="font-size:12px; color:#475569;">outside $(& $E $CompanyName)</div></td>
        <td style="width:10px;"></td>
        <td style="padding:12px 18px; background:#f1f5f9; border-radius:8px; text-align:center;"><div style="font-size:26px; font-weight:800; color:#0f172a;">$($Inside.Count)</div><div style="font-size:12px; color:#475569;">inside $(& $E $CompanyName)</div></td>
      </tr></table>
    </td></tr>
$Alert
$(& $Section "Shared outside $CompanyName" 'People outside your organization can open these. &ldquo;Anyone with the link&rdquo; means no sign-in is needed: whoever has the link, including anyone it is forwarded to, can open it.' $Outside $MaxOutsideRows)
$(& $Section "Shared inside $CompanyName" 'Only people in your organization can open these.' $Inside $MaxInsideRows)
    <tr><td style="padding:26px 32px 0 32px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#eff6ff; border-left:4px solid #2563eb; border-radius:4px;">
        <tr><td style="padding:14px 18px; font-size:14px; line-height:1.7; color:#334155;"><strong style="color:#0f172a;">How to stop sharing something</strong><br>Click the item above to open it in OneDrive. Choose <strong>Share</strong>, then <strong>Manage access</strong>. Find the link or person and choose <strong>Remove</strong> (or <strong>Stop sharing</strong>).</td></tr>
      </table>
    </td></tr>
    <tr><td style="padding:12px 32px 0 32px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f1f5f9; border-radius:8px;">
        <tr><td style="padding:14px 18px; font-size:14px; line-height:1.6; color:#334155;"><strong style="color:#0f172a;">Questions, or something here you don't recognise?</strong> Just reply to this email and it will reach our help desk, or call <strong style="color:#0f172a;">$(& $E $SupportPhone)</strong>.</td></tr>
      </table>
    </td></tr>
    <tr><td style="padding:24px 32px 28px 32px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
        <tr><td style="border-top:1px solid #e2e8f0; padding-top:14px; font-size:12px; line-height:1.6; color:#64748b;">$(& $E $BrandName), IT support for $(& $E $CompanyName). You get this email weekly while you have shared items in OneDrive.<br><a href="mailto:$(& $E $SupportEmail)" style="color:#64748b; text-decoration:none;">$(& $E $SupportEmail)</a></td></tr>
      </table>
    </td></tr>
  </table>
</td></tr>
</table>
</body></html>
"@

    return [PSCustomObject]@{ Subject = $Subject; Html = $Html }
}
