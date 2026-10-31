function Get-CIPPDeviceCodeSignIns {
    <#
    .SYNOPSIS
        Summarises a tenant's device-code (OAuth device authorization grant) sign-ins, so legitimate uses can be
        excluded before a "block device code flow" Conditional Access policy is enforced.
    .DESCRIPTION
        Reads beta/auditLogs/signIns filtered on authenticationProtocol eq 'deviceCode'. That filter is not
        indexed: a 30-day window times out (100 s) in busy tenants, while a one-day window returns quickly. So
        the window is walked one UTC day at a time, newest first. A day that fails for any reason other than
        licensing is recorded in Errors and the rest still run, so a partial answer is labelled as partial
        instead of passing for "none found".

        Sign-in logs need Entra ID P1. Without it the first call fails with a licence error and the function
        returns Licensed = $false with a clear message and an empty summary.

        Summary rows are one per user + app + device: UPN, app, device, count, successes, failures, first and
        last seen (US Central and UTC), IP addresses and locations.
        Aspendora fork addition (Vikunja CIPP-8).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [int]$Days = 30,
        # For tests: the instant the look-back is measured from.
        [datetime]$Now = (Get-Date).ToUniversalTime()
    )

    $Days = [math]::Max(1, [math]::Min(30, $Days))
    $Now = $Now.ToUniversalTime()
    $Central = try { [System.TimeZoneInfo]::FindSystemTimeZoneById('America/Chicago') } catch { $null }
    $When = {
        param($Value)
        if (-not $Value) { return '' }
        $Utc = ([datetimeoffset]$Value).UtcDateTime
        if ($Central) {
            $Local = [System.TimeZoneInfo]::ConvertTimeFromUtc($Utc, $Central)
            $Zone = if ($Central.IsDaylightSavingTime($Local)) { 'CDT' } else { 'CST' }
            return "$($Local.ToString('yyyy-MM-dd HH:mm')) $Zone ($($Utc.ToString('HH:mm')) UTC)"
        }
        return "$($Utc.ToString('yyyy-MM-dd HH:mm')) UTC"
    }

    $Report = [ordered]@{
        Tenant       = $TenantFilter
        Days         = $Days
        Licensed     = $true
        Message      = ''
        TotalSignIns = 0
        DaysQueried  = 0
        DaysFailed   = 0
        Summary      = @()
        Errors       = @()
    }
    $Errors = [System.Collections.Generic.List[string]]::new()
    $SignIns = [System.Collections.Generic.List[object]]::new()
    $Select = 'id,createdDateTime,userPrincipalName,userId,appDisplayName,appId,ipAddress,location,status,deviceDetail,clientAppUsed'

    for ($i = 0; $i -lt $Days; $i++) {
        $End = $Now.AddDays(-$i)
        $Start = $Now.AddDays(-($i + 1))
        $Filter = "createdDateTime ge $($Start.ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime lt $($End.ToString('yyyy-MM-ddTHH:mm:ssZ')) and authenticationProtocol eq 'deviceCode'"
        try {
            $Page = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=$Filter&`$select=$Select&`$top=999" -tenantid $TenantFilter -ErrorAction Stop | Where-Object { $_.id })
            foreach ($S in $Page) { $SignIns.Add($S) }
            $Report.DaysQueried++
        } catch {
            $Err = (Get-CippException -Exception $_).NormalizedError
            if ($Err -match 'premium|license|Authentication_RequestFromNonPremiumTenantOrB2CTenant') {
                $Report.Licensed = $false
                $Report.Message = 'This tenant has no Entra ID P1 (or higher) licence, so its sign-in logs cannot be read and device-code use cannot be reported. Device-code blocking through Conditional Access also needs P1.'
                $Report.Errors = @($Err)
                return [pscustomobject]$Report
            }
            $Report.DaysFailed++
            $Errors.Add("$($Start.ToString('yyyy-MM-dd')): $Err")
        }
    }

    # Graph can return the same event twice across window edges; keep one of each.
    $Unique = @($SignIns | Group-Object id | ForEach-Object { $_.Group[0] })
    $Report.TotalSignIns = $Unique.Count

    $Report.Summary = @(
        $Unique | Group-Object {
            $Device = $_.deviceDetail.deviceId ?? $_.deviceDetail.displayName ?? "$($_.deviceDetail.operatingSystem)|$($_.deviceDetail.browser)"
            "$(([string]$_.userPrincipalName).ToLower())|$($_.appId)|$Device"
        } | ForEach-Object {
            $Rows = @($_.Group | Sort-Object { [datetimeoffset]$_.createdDateTime })
            $First = $Rows[0]
            $Last = $Rows[-1]
            $Ok = @($Rows | Where-Object { [int]$_.status.errorCode -eq 0 }).Count
            $Dev = $Last.deviceDetail
            $DeviceLabel = @($Dev.displayName, $Dev.operatingSystem, $Dev.browser) | Where-Object { $_ }
            [pscustomobject]@{
                UserPrincipalName = $Last.userPrincipalName
                AppDisplayName    = $Last.appDisplayName
                AppId             = $Last.appId
                Device            = if ($DeviceLabel) { $DeviceLabel -join ' / ' } else { 'Unknown' }
                DeviceId          = $Dev.deviceId
                Count             = $Rows.Count
                SuccessCount      = $Ok
                FailureCount      = $Rows.Count - $Ok
                FirstSeen         = & $When $First.createdDateTime
                LastSeen          = & $When $Last.createdDateTime
                LastSeenUtc       = ([datetimeoffset]$Last.createdDateTime).UtcDateTime.ToString('o')
                IPAddresses       = (@($Rows.ipAddress | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
                Locations         = (@($Rows | ForEach-Object { (@($_.location.city, $_.location.countryOrRegion) | Where-Object { $_ }) -join ', ' } | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
            }
        } | Sort-Object -Property @{ Expression = 'LastSeenUtc'; Descending = $true }
    )

    $Report.Errors = @($Errors)
    $Report.Message = if ($Report.DaysFailed -gt 0) {
        "$($Report.DaysFailed) of $Days day(s) could not be read (see Errors); the summary covers only the days that were. Do not treat it as complete."
    } elseif ($Report.TotalSignIns -eq 0) {
        "No device-code sign-ins in the last $Days day(s)."
    } else {
        "$($Report.TotalSignIns) device-code sign-in(s) in the last $Days day(s) across $($Report.Summary.Count) user/app/device combination(s). Exclude only the legitimate ones (e.g. Teams Rooms, a named admin's CLI) before enforcing the block policy."
    }
    [pscustomobject]$Report
}
