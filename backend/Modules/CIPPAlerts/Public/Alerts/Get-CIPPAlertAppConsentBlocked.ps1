function Get-CIPPAlertAppConsentBlocked {
    <#
    .SYNOPSIS
        Alert when a user is blocked from signing in to an app because consent is required
    .DESCRIPTION
        Sweeps the sign-in logs for consent failures - 65001 (user or admin has not consented) and
        90094 (admin consent required) - and raises one alert per application per blocking
        episode.

        WHY THE SIGN-IN LOG AND NOT THE CONSENT REQUEST QUEUE: the obvious source would be
        identityGovernance/appConsent/appConsentRequests, but that queue is only populated when the
        tenant has the admin consent request workflow enabled, and it is DISABLED on 7 of 8 client
        tenants (surveyed 2026-09-17). On those tenants the user hits a dead end with no "ask your
        admin" button, nothing is queued, and nobody is told - which is exactly the case that needs
        catching. Sign-in error codes are written regardless of tenant configuration, need no
        per-tenant setup, and need no licensed reviewer mailbox, because the notification is this
        alert rather than Microsoft's email.

        The alert carries the admin consent URL so the ticket is actionable without further lookup.

        Grouping is per application, not per user: ten people blocked on one app is one problem.

        Dedup is the AlertLifecycle (CIPP 11.0) in -Append (event stream) mode, keyed on the app id:
        an app notifies once, stays Open while it keeps being blocked, and resolves as stale after
        30 days without a failure - so a later block is a new episode and notifies once more. (The
        fork's earlier DeltaCompare baseline never re-notified an app, even months later.)
        Initialize-CIPPAlertLifecycleBaseline hands that baseline over once, so every app it already
        knew stays quiet, and a never-baselined tenant still surfaces nothing on its first run.
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        [Parameter(Mandatory)]
        $TenantFilter
    )

    # Lookback is bounded because this filter is expensive: a 30-day window timed out against a
    # busy tenant during testing. The alert runs on a schedule, and the lifecycle below means a
    # short window loses nothing - an app blocked today is still new to the lifecycle today.
    $LookbackHours = if ($InputValue.AppConsentBlockedLookbackHours) { [int]$InputValue.AppConsentBlockedLookbackHours } else { 24 }
    # Backstop against a first-ever run on a tenant with a long history, or a sudden burst. The
    # excess is still recorded as seen so it cannot re-surface later and arrive as a second flood.
    $MaxSurfacedPerCycle = if ($InputValue.AppConsentBlockedMaxPerCycle) { [int]$InputValue.AppConsentBlockedMaxPerCycle } else { 10 }

    try {
        $Cutoff = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $Uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $Cutoff and (status/errorCode eq 65001 or status/errorCode eq 90094)&`$select=createdDateTime,userPrincipalName,appDisplayName,appId,resourceDisplayName,status&`$top=200"

        $SignIns = @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -noPagination $true -ErrorAction Stop)

        # Resolve the customer id for the admin consent URL. The alert is still useful without it,
        # so a failure here degrades the link rather than the whole alert.
        $CustomerId = $null
        try { $CustomerId = (Get-Tenants -TenantFilter $TenantFilter).customerId } catch {}

        $Blocked = @{}
        foreach ($SignIn in $SignIns) {
            $AppId = [string]$SignIn.appId
            if (-not $AppId) { continue }
            if (-not $Blocked.ContainsKey($AppId)) {
                $Blocked[$AppId] = [PSCustomObject]@{
                    AppId      = $AppId
                    AppName    = [string]$SignIn.appDisplayName
                    Resource   = [string]$SignIn.resourceDisplayName
                    Users      = [System.Collections.Generic.HashSet[string]]::new()
                    ErrorCodes = [System.Collections.Generic.HashSet[string]]::new()
                    FirstSeen  = [datetime]$SignIn.createdDateTime
                    LastSeen   = [datetime]$SignIn.createdDateTime
                    Count      = 0
                }
            }
            $Entry = $Blocked[$AppId]
            if ($SignIn.userPrincipalName) { $null = $Entry.Users.Add([string]$SignIn.userPrincipalName) }
            if ($SignIn.status.errorCode) { $null = $Entry.ErrorCodes.Add([string]$SignIn.status.errorCode) }
            $When = [datetime]$SignIn.createdDateTime
            if ($When -lt $Entry.FirstSeen) { $Entry.FirstSeen = $When }
            if ($When -gt $Entry.LastSeen) { $Entry.LastSeen = $When }
            $Entry.Count++
        }

        $AlertData = @(foreach ($AppId in $Blocked.Keys) {
                $Info = $Blocked[$AppId]
                $ConsentUrl = if ($CustomerId) { "https://login.microsoftonline.com/$CustomerId/adminconsent?client_id=$AppId" } else { 'unavailable - could not resolve tenant id' }
                [PSCustomObject]@{
                    # Lifecycle identity (Get-AlertContentHash keys on Id): one row per application.
                    'Id'                = $Info.AppId
                    'Application'       = $Info.AppName
                    'Application Id'    = $Info.AppId
                    'Resource'          = $Info.Resource
                    'Users Blocked'     = $Info.Users.Count
                    'Users'             = (@($Info.Users) | Sort-Object) -join ', '
                    'Error Codes'       = (@($Info.ErrorCodes) | Sort-Object) -join ', '
                    'Attempts'          = $Info.Count
                    'First Seen'        = $Info.FirstSeen.ToString('u')
                    'Last Seen'         = $Info.LastSeen.ToString('u')
                    'Admin Consent URL' = $ConsentUrl
                    'Tenant'            = $TenantFilter
                }
            })

        $CmdletName = [string]$MyInvocation.MyCommand
        Initialize-CIPPAlertLifecycleBaseline -CmdletName $CmdletName -TenantFilter $TenantFilter `
            -BaselinePartition 'AppConsentBlockedDelta' -CurrentItems $AlertData `
            -KnownItemsFromBaseline { param($Ids) foreach ($Id in $Ids) { @{ Id = [string]$Id } } }

        # -Append: the sign-in window is a stream of events, not the full picture, so an app absent
        # from this window is not "fixed". Open rows unseen for 30 days are resolved as stale.
        $New = @(Write-AlertTrace -cmdletName $CmdletName -tenantFilter $TenantFilter -data $AlertData -Append | Where-Object { $_ })
        if ($New.Count -eq 0) { return }

        if ($New.Count -gt $MaxSurfacedPerCycle) {
            # Suppression is never silent - a swallowed burst looks identical to a working alert.
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "App consent alert: $($New.Count) newly blocked applications exceeded the per-cycle cap of $MaxSurfacedPerCycle; surfaced $MaxSurfacedPerCycle. The remainder are recorded as open and will not re-surface." -sev Warning
        }
        $New | Select-Object -First $MaxSurfacedPerCycle
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Could not check for blocked app consent for $($TenantFilter): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
    }
}
