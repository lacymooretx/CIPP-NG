function ConvertTo-CIPPAdminInventoryHtml {
    <#
    .SYNOPSIS
        Renders a Get-CIPPAdminInventory result as the body of the Hudu article "Microsoft 365 admins — <client>".
    .DESCRIPTION
        Pure function. Contains no secrets: names, roles, MFA method types and flags only. Times in US Central.
        Aspendora fork addition (onboarding Phase 3).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Inventory,
        [string]$ClientName
    )
    $Enc = { param($S) [System.Net.WebUtility]::HtmlEncode([string]$S) }
    $Tz = try { [TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { [TimeZoneInfo]::FindSystemTimeZoneById('Central Standard Time') }
    $Utc = ([datetimeoffset]$Inventory.GeneratedUtc).UtcDateTime
    $Local = [TimeZoneInfo]::ConvertTimeFromUtc($Utc, $Tz)
    $Zone = if ($Tz.IsDaylightSavingTime($Local)) { 'CDT' } else { 'CST' }
    $YesNo = { param($V) if ($null -eq $V) { 'unknown' } elseif ($V) { 'yes' } else { '<b>no</b>' } }

    $Admins = @($Inventory.Admins)
    $Flagged = @($Admins | Where-Object { @($_.Flags).Count -gt 0 })
    $BG = @($Admins | Where-Object BreakGlass)
    $Rows = foreach ($A in $Admins) {
        $Flags = (@($A.Flags) | ForEach-Object { switch ($_) {
                    'PermanentGA' { 'Permanent Global Admin (not break-glass)' } 'ServicePrincipalGA' { 'App holds Global Admin' } 'Synced' { 'Synced from on-premises AD' }
                    'NoMFA' { 'No MFA method' } 'NotPhishResistant' { 'No phishing-resistant method' } 'DeletedPrincipal' { 'Principal deleted' } default { $_ } } }) -join '; '
        "<tr><td>$(& $Enc $A.Name)<br><small>$(& $Enc $A.UserPrincipalName)</small></td><td>$(& $Enc $A.Type)$(if ($A.BreakGlass) { '<br><b>break-glass</b>' })$(if ($A.Enabled -eq $false) { '<br>disabled' })</td><td>$(& $Enc $A.Roles)</td><td>$(& $YesNo $A.MFA)</td><td>$(& $YesNo $A.PhishResistant)</td><td><small>$(& $Enc $A.Methods)</small></td><td>$(& $Enc $Flags)</td></tr>"
    }
    $NotesHtml = if (@($Inventory.Notes).Count) { "<p><i>$((@($Inventory.Notes) | ForEach-Object { & $Enc $_ }) -join ' ')</i></p>" } else { '' }
    @"
<p><b>Generated automatically by CIPP</b> on $($Local.ToString('yyyy-MM-dd HH:mm')) $Zone. Refreshed weekly and after break-glass provisioning. Do not edit by hand; changes are overwritten. This article contains no credentials. Break-glass passwords are set by ControlR and kept in Keeper (MSP shared folder) and in this company's Hudu passwords.</p>
<p><b>$($Admins.Count)</b> privileged role holder(s); <b>$($BG.Count)</b> registered break-glass account(s) (standard: 2); <b>$($Flagged.Count)</b> flagged.</p>
$NotesHtml
<table><thead><tr><th>Who</th><th>Type</th><th>Roles</th><th>MFA</th><th>Phishing-resistant</th><th>Methods</th><th>Flags</th></tr></thead><tbody>
$($Rows -join "`n")
</tbody></table>
<p>Source: CIPP Get-CIPPAdminInventory ($(& $Enc $Inventory.Tenant)). Break-glass standard and alerts: Hudu article 737.</p>
"@
}
