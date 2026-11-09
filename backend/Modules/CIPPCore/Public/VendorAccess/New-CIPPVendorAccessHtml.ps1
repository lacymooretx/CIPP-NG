function New-CIPPVendorAccessHtml {
    <#
    .SYNOPSIS
        Renders the weekly Vendor Access email from a Get-CIPPVendorAccessSnapshot result.
    .DESCRIPTION
        Summary tiles (third-party access, organisations, new this week, high risk, stale, sign-in unknown), then
        lists of new, removed, high-risk and stale items, then one section per tenant. Inline styles only, so mail
        clients render it. Times are US Central. Send-CIPPAlert runs %token% replacement over the body; it only touches
        known token names, so the table widths' percent signs are safe. Aspendora fork addition (Vendor Access).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Snapshot,
        [string]$ReportUrl = 'https://cipp.aspendora.com/tenant/reports/vendor-access',
        [int]$StaleDays = 45,
        # Rows shown in the cross-tenant high-risk and stale lists; the per-tenant sections always list everything.
        [int]$MaxListRows = 40
    )

    $Zone = try { [TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { [TimeZoneInfo]::FindSystemTimeZoneById('Central Standard Time') }
    $Central = {
        param($Utc)
        if (-not $Utc) { return '' }
        $D = ([datetimeoffset]$Utc).UtcDateTime
        $L = [TimeZoneInfo]::ConvertTimeFromUtc($D, $Zone)
        $Abbr = if ($Zone.IsDaylightSavingTime($L)) { 'CDT' } else { 'CST' }
        '{0} {1}' -f $L.ToString('ddd MMM d, yyyy h:mm tt', [cultureinfo]::InvariantCulture), $Abbr
    }
    $CentralDate = {
        param($Utc)
        if (-not $Utc) { return 'unknown' }
        [TimeZoneInfo]::ConvertTimeFromUtc(([datetimeoffset]$Utc).UtcDateTime, $Zone).ToString('MMM d, yyyy', [cultureinfo]::InvariantCulture)
    }
    $E = { param($Text) [System.Net.WebUtility]::HtmlEncode([string]$Text) }
    $Short = { param($Text, $Max = 260) $T = [string]$Text; if ($T.Length -gt $Max) { $T.Substring(0, $Max) + ' …' } else { $T } }
    $KindLabel = @{ App = 'App'; ForeignRoleHolder = 'Outside admin'; GuestRoleHolder = 'Guest admin'; ServiceProvider = 'Service provider' }
    $RiskColour = @{ Critical = '#7f1d1d'; High = '#b91c1c'; Medium = '#b45309'; Low = '#4b5563' }
    $RiskBg = @{ Critical = '#fee2e2'; High = '#fee2e2'; Medium = '#fef3c7'; Low = '#f3f4f6' }
    $Rank = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
    $Badge = { param($Risk) "<span style=`"display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;color:$($RiskColour[[string]$Risk] ?? '#4b5563');background:$($RiskBg[[string]$Risk] ?? '#f3f4f6')`">$(& $E $Risk)</span>" }
    $SignIn = {
        param($Item)
        switch ([string]$Item.SignInActivity) {
            'Unknown' { '<span style="color:#6b7280">Unknown (no Entra ID P1)</span>' }
            'Not applicable' { '<span style="color:#6b7280">n/a</span>' }
            'No sign-in recorded' { '<span style="color:#b91c1c">No sign-in recorded</span>' }
            default {
                $When = & $CentralDate $Item.LastSignInDateTime
                $Colour = if ($Item.Stale -eq $true) { '#b91c1c' } else { '#111827' }
                "<span style=`"color:$Colour`">$When ($($Item.DaysSinceLastSignIn) days)</span>"
            }
        }
    }
    $Who = {
        param($Item)
        $Org = & $E $Item.Organisation
        if ($Item.Vendor -and $Item.Vendor -ne $Item.Organisation) { "$Org<br><span style=`"color:#6b7280;font-size:12px`">$(& $E $Item.Vendor) &middot; $(& $E $Item.OrganisationType)</span>" }
        else { "$Org<br><span style=`"color:#6b7280;font-size:12px`">$(& $E $Item.OrganisationType)</span>" }
    }
    $Th = 'style="text-align:left;padding:6px 8px;border-bottom:2px solid #e5e7eb;font-size:12px;color:#374151;background:#f9fafb"'
    $Td = 'style="padding:6px 8px;border-bottom:1px solid #f3f4f6;font-size:13px;vertical-align:top"'
    $Table = {
        param($Rows, [switch]$WithTenant)
        $Sb = [System.Text.StringBuilder]::new()
        [void]$Sb.Append('<table cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;width:100%;margin:0 0 8px 0">')
        [void]$Sb.Append("<tr>$(if ($WithTenant) { "<th $Th>Tenant</th>" })<th $Th>Type</th><th $Th>Who</th><th $Th>Organisation</th><th $Th>Access</th><th $Th>Risk</th><th $Th>Last sign-in</th></tr>")
        foreach ($I in $Rows) {
            $Flags = @()
            if ($I.IsNew) { $Flags += '<span style="color:#1d4ed8;font-weight:600">NEW</span>' }
            if ($I.Removed) { $Flags += "<span style=`"color:#065f46;font-weight:600`">REMOVED $(& $CentralDate $I.RemovedAt)</span>" }
            if ($I.Enabled -eq $false) { $Flags += '<span style="color:#6b7280">disabled</span>' }
            if ([int]$I.NewCredentials -gt 0) { $Flags += "<span style=`"color:#b91c1c;font-weight:600`">$([int]$I.NewCredentials) new credential(s)</span>" }
            $FlagText = if ($Flags) { '<br>' + ($Flags -join ' &middot; ') } else { '' }
            [void]$Sb.Append("<tr>$(if ($WithTenant) { "<td $Td>$(& $E ($I.TenantName ?? $I.Tenant))</td>" })<td $Td>$(& $E $KindLabel[[string]$I.Kind])</td><td $Td><strong>$(& $E $I.Name)</strong>$FlagText</td><td $Td>$(& $Who $I)</td><td $Td>$(& $E (& $Short $I.Access))</td><td $Td>$(& $Badge $I.Risk)</td><td $Td>$(& $SignIn $I)</td></tr>")
        }
        [void]$Sb.Append('</table>')
        $Sb.ToString()
    }
    $Sort = { param($Rows) @($Rows | Sort-Object @{ Expression = { $Rank[[string]$_.Risk] }; Descending = $true }, TenantName, Name) }

    $S = $Snapshot.Summary
    $All = @($Snapshot.Items)
    $Current = @($All | Where-Object { -not $_.Removed -and $_.IsThirdParty })
    $New = & $Sort @($All | Where-Object { $_.IsNew })
    $Gone = & $Sort @($All | Where-Object { $_.Removed })
    $High = & $Sort @($Current | Where-Object { $_.Risk -in @('Critical', 'High') })
    $Stale = & $Sort @($Current | Where-Object { $_.Stale -eq $true })

    $Tile = {
        param($Value, $Label, $Colour = '#111827')
        "<td style=`"padding:4px`" valign=`"top`"><div style=`"border:1px solid #e5e7eb;border-radius:8px;padding:10px 12px;min-width:110px`"><div style=`"font-size:24px;font-weight:700;color:$Colour`">$Value</div><div style=`"font-size:12px;color:#6b7280`">$Label</div></div></td>"
    }
    $Section = { param($Title, $Body) "<h2 style=`"font-size:16px;margin:22px 0 6px 0;color:#111827`">$Title</h2>$Body" }
    $Capped = {
        param($Rows)
        if ($Rows.Count -le $MaxListRows) { return (& $Table $Rows -WithTenant) }
        (& $Table @($Rows | Select-Object -First $MaxListRows) -WithTenant) + "<div style=`"font-size:12px;color:#6b7280`">Showing the top $MaxListRows of $($Rows.Count). The rest are in the tenant sections below and in <a href=`"$ReportUrl`" style=`"color:#B71A28`">the report</a>.</div>"
    }

    $Html = [System.Text.StringBuilder]::new()
    [void]$Html.Append('<div style="font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#111827;max-width:1100px">')
    [void]$Html.Append("<div style=`"border-top:4px solid #B71A28;padding-top:10px`"><h1 style=`"font-size:20px;margin:0`">Vendor access across client tenants</h1>")
    [void]$Html.Append("<div style=`"color:#6b7280;font-size:13px;margin-top:4px`">Data from $(& $Central $Snapshot.GeneratedAt) &middot; $($S.Tenants) tenants &middot; <a href=`"$ReportUrl`" style=`"color:#B71A28`">Open the report in CIPP</a></div></div>")
    [void]$Html.Append('<table cellpadding="0" cellspacing="0" style="margin:14px 0 4px -4px"><tr>')
    [void]$Html.Append((& $Tile $S.ThirdPartyItems 'outside parties with access'))
    [void]$Html.Append((& $Tile $S.Organisations 'organisations'))
    [void]$Html.Append((& $Tile $S.New 'new since last week' $(if ($S.New -gt 0) { '#1d4ed8' } else { '#111827' })))
    [void]$Html.Append((& $Tile $S.HighRisk 'high or critical risk' $(if ($S.HighRisk -gt 0) { '#b91c1c' } else { '#111827' })))
    [void]$Html.Append((& $Tile $S.Stale "stale ($StaleDays+ days)" $(if ($S.Stale -gt 0) { '#b45309' } else { '#111827' })))
    [void]$Html.Append((& $Tile $S.SignInUnknown 'sign-in unknown'))
    [void]$Html.Append('</tr></table>')
    [void]$Html.Append("<div style=`"font-size:12px;color:#6b7280`">$($S.Apps) apps ($($S.AppsWithPermissions) with API permissions) &middot; $($S.ForeignRoleHolders) outside admin groups/accounts (other partners' GDAP/DAP) &middot; $($S.GuestRoleHolders) guest admins &middot; $($S.ServiceProviders) service-provider partners &middot; $($S.Removed) removed since last week. Aspendora's own CIPP partner tenant is not counted.</div>")

    # Errors can arrive as $null or an empty string after a JSON round trip; count only real messages.
    $Failed = @($Snapshot.Tenants | Where-Object { $_.LastError -or @($_.Errors | Where-Object { $_ }).Count -gt 0 })
    if ($Failed.Count -gt 0) {
        $List = ($Failed | ForEach-Object { "<li><strong>$(& $E $_.TenantName)</strong>: $(& $E ((@($_.LastError) + @($_.Errors) | Where-Object { $_ }) -join '; '))</li>" }) -join ''
        [void]$Html.Append((& $Section 'Could not be fully checked' "<ul style=`"font-size:13px;color:#b45309;margin:0`">$List</ul>"))
    }
    [void]$Html.Append((& $Section "New since last week ($($New.Count))" $(if ($New.Count) { & $Table $New -WithTenant } else { '<div style="font-size:13px;color:#6b7280">Nothing new.</div>' })))
    if ($Gone.Count) { [void]$Html.Append((& $Section "Removed since last week ($($Gone.Count))" (& $Table $Gone -WithTenant))) }
    [void]$Html.Append((& $Section "High or critical risk ($($High.Count))" $(if ($High.Count) { & $Capped $High } else { '<div style="font-size:13px;color:#6b7280">None.</div>' })))
    [void]$Html.Append((& $Section "Stale: no sign-in for $StaleDays+ days ($($Stale.Count))" $(if ($Stale.Count) { (& $Capped $Stale) + '<div style="font-size:12px;color:#6b7280">Stale access is a candidate for removal: a vendor that no longer signs in does not need standing access.</div>' } else { '<div style="font-size:13px;color:#6b7280">None.</div>' })))

    foreach ($T in @($Snapshot.Tenants | Sort-Object TenantName)) {
        $Rows = & $Sort @($Current | Where-Object Tenant -EQ $T.Tenant)
        $Own = @($All | Where-Object { $_.Tenant -eq $T.Tenant -and -not $_.Removed -and -not $_.IsThirdParty }).Count
        $Note = "<div style=`"font-size:12px;color:#6b7280`">Checked $(& $Central $T.GeneratedAt)$(if (-not $T.SignInActivityAvailable) { ' &middot; app sign-in data unavailable (no Entra ID P1), shown as Unknown' })$(if ($Own) { " &middot; $Own item(s) are Aspendora's own access, not listed" })</div>"
        $Body = if ($Rows.Count) { (& $Table $Rows) + $Note } else { '<div style="font-size:13px;color:#6b7280">No outside access found.</div>' + $Note }
        [void]$Html.Append((& $Section "$(& $E $T.TenantName) ($($Rows.Count))" $Body))
    }
    [void]$Html.Append("<div style=`"font-size:11px;color:#9ca3af;margin-top:24px;border-top:1px solid #e5e7eb;padding-top:8px`">Sent weekly by CIPP (Aspendora) on Mondays at 07:00 US Central. Apps come from CIPP's reporting database (refreshed nightly); directory roles and cross-tenant partners are read live. To cut off a vendor, see the Vendor Access article in Hudu.</div></div>")
    $Html.ToString()
}
