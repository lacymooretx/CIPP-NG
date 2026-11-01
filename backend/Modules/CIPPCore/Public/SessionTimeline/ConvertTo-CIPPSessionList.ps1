function ConvertTo-CIPPSessionList {
    <#
    .SYNOPSIS
        Groups sign-ins by sessionId into one row per session, newest first. Pure; see Get-CIPPUserRecentSessions.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([AllowNull()][object[]]$SignIns)

    $WithSession = @($SignIns | Where-Object { $_ -and $_.sessionId })
    $Sessions = foreach ($Group in @($WithSession | Group-Object -Property { ([string]$_.sessionId).ToLowerInvariant() })) {
        $Times = @($Group.Group | ForEach-Object { ConvertTo-CIPPCentralTime -Value $_.createdDateTime } | Where-Object { $_ } | Sort-Object -Property Utc)
        $Newest = @($Group.Group | Sort-Object -Property { (ConvertTo-CIPPCentralTime -Value $_.createdDateTime).Utc } -Descending)[0]
        $Failures = @($Group.Group | Where-Object { $_.status -and [string]$_.status.errorCode -ne '0' -and $null -ne $_.status.errorCode }).Count
        [pscustomobject]@{
            SessionId         = $Group.Name
            UserPrincipalName = [string]$Newest.userPrincipalName
            FirstSignIn       = if ($Times.Count) { $Times[0].Display } else { $null }
            LastSignIn        = if ($Times.Count) { $Times[-1].Display } else { $null }
            LastSignInUtc     = if ($Times.Count) { $Times[-1].Utc } else { $null }
            SignIns           = $Group.Count
            Failures          = $Failures
            IPAddresses       = (@($Group.Group | ForEach-Object { [string]$_.ipAddress } | Where-Object { $_ } | Select-Object -Unique) -join ', ')
            Countries         = (@($Group.Group | ForEach-Object { [string]$_.location.countryOrRegion } | Where-Object { $_ } | Select-Object -Unique) -join ', ')
            Apps              = (@($Group.Group | ForEach-Object { [string]$_.appDisplayName } | Where-Object { $_ } | Select-Object -Unique) -join ', ')
            UserAgent         = [string]$Newest.userAgent
        }
    }
    # Wrapped so an empty or single result reaches the caller as an array, not $null or a bare object.
    , @($Sessions | Sort-Object -Property LastSignInUtc -Descending)
}
