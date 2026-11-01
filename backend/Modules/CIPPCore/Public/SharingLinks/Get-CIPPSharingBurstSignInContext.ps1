function Get-CIPPSharingBurstSignInContext {
    <#
    .SYNOPSIS
        Looks for a risky or unfamiliar successful sign-in by an account in the 24 hours before it started mass sharing.
    .DESCRIPTION
        Aspendora fork addition (Vikunja CIPP-13). Reads the account's successful sign-ins (interactive and
        non-interactive) in the 24 hours before Before, and its successful sign-ins in the 7 days before that as a
        baseline. A sign-in is notable when Entra rated it risky (riskLevelDuringSignIn low/medium/high, a risk
        event, or riskState atRisk / confirmedCompromised - risk detail needs Entra ID P2 and reads 'hidden'
        without it) or when it came from a country the account did not sign in from in the baseline.

        Sign-in logs need Entra ID P1. Without it the context reports Checked = $false rather than failing.
    .PARAMETER TenantFilter
        Tenant default domain.
    .PARAMETER UserPrincipalName
        The account.
    .PARAMETER Before
        When the sharing started (UTC).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$TenantFilter,
        [Parameter(Mandatory = $true)][string]$UserPrincipalName,
        [Parameter(Mandatory = $true)][datetime]$Before
    )

    $Fmt = 'yyyy-MM-ddTHH:mm:ssZ'
    $End = $Before.ToUniversalTime().AddMinutes(5)
    $Start = $End.AddHours(-24)
    $BaselineStart = $Start.AddDays(-7)
    $Upn = $UserPrincipalName -replace "'", "''"
    $Select = 'createdDateTime,ipAddress,location,appDisplayName,status,riskLevelDuringSignIn,riskState,riskEventTypes_v2,isInteractive'
    $Uri = { param($From, $To) "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=userPrincipalName eq '$Upn' and createdDateTime ge $($From.ToString($Fmt)) and createdDateTime le $($To.ToString($Fmt)) and status/errorCode eq 0 and (signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser'))&`$select=$Select&`$top=200" }

    try {
        $Window = @(New-GraphGetRequest -uri (& $Uri $Start $End) -tenantid $TenantFilter -noPagination $true -ErrorAction Stop | Where-Object { $_ })
    } catch {
        $Message = $_.Exception.Message
        $Reason = if ($Message -match 'premium|P1|license|Authentication_RequestFromNonPremiumTenantOrB2CTenant') { 'Sign-in logs need Entra ID P1; not checked.' } else { "Sign-in check failed: $Message" }
        return [pscustomobject]@{ Checked = $false; Notable = $false; Summary = $Reason; SignIns = @() }
    }
    $Baseline = @(try { New-GraphGetRequest -uri (& $Uri $BaselineStart $Start) -tenantid $TenantFilter -noPagination $true -ErrorAction Stop | Where-Object { $_ } } catch { @() })
    $KnownCountries = @($Baseline | ForEach-Object { [string]$_.location.countryOrRegion } | Where-Object { $_ } | Select-Object -Unique)

    $Notable = foreach ($S in $Window) {
        $Reasons = [System.Collections.Generic.List[string]]::new()
        if ([string]$S.riskLevelDuringSignIn -in @('low', 'medium', 'high')) { $Reasons.Add("risk $($S.riskLevelDuringSignIn)") }
        if ([string]$S.riskState -in @('atRisk', 'confirmedCompromised')) { $Reasons.Add("risk state $($S.riskState)") }
        if (@($S.riskEventTypes_v2 | Where-Object { $_ }).Count -gt 0) { $Reasons.Add("risk events: $(@($S.riskEventTypes_v2) -join ', ')") }
        $Country = [string]$S.location.countryOrRegion
        if ($Country -and $KnownCountries.Count -gt 0 -and $KnownCountries -notcontains $Country) { $Reasons.Add("country $Country not seen in the previous 7 days") }
        if ($Reasons.Count -eq 0) { continue }
        [pscustomobject]@{
            When     = $S.createdDateTime
            IP       = $S.ipAddress
            Location = (@($S.location.city, $S.location.countryOrRegion) | Where-Object { $_ }) -join ', '
            App      = $S.appDisplayName
            Reasons  = $Reasons -join '; '
        }
    }
    $Notable = @($Notable | Sort-Object When)
    $Summary = if ($Notable.Count -gt 0) {
        (@($Notable | Select-Object -First 3 | ForEach-Object { "$(([datetime]$_.When).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC from $($_.IP) ($($_.Location)) to $($_.App): $($_.Reasons)" }) -join ' | ') + $(if ($Notable.Count -gt 3) { " (+$($Notable.Count - 3) more)" })
    } elseif ($Window.Count -eq 0) {
        'No successful sign-in in the 24 h before the sharing (it may have used a token issued earlier).'
    } else {
        "$($Window.Count) successful sign-in(s) in the 24 h before; none risky or from a new country."
    }
    [pscustomobject]@{ Checked = $true; Notable = ($Notable.Count -gt 0); Summary = $Summary; SignIns = $Notable }
}
