function Get-CIPPAlertAppConsentBlocked {
    <#
    .SYNOPSIS
        Alert when a user is blocked from signing in to an app because consent is required
    .DESCRIPTION
        Sweeps the sign-in logs for consent failures - 65001 (user or admin has not consented) and
        90094 (admin consent required) - and raises one alert per application that has never been
        seen blocked in this tenant before.

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
    # busy tenant during testing. The alert runs on a schedule, and the delta baseline below means
    # a short window loses nothing - an app blocked today is still new to the baseline today.
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

        # A window with no consent failures must not clear the baseline - that would make every
        # previously-seen app new again on the next failure and re-ticket the whole set.
        if ($Blocked.Count -eq 0) { return }

        # Baseline of every app EVER seen blocked in this tenant, append-only.
        $DeltaTable = Get-CIPPTable -Table DeltaCompare
        $EscapedTenant = $TenantFilter -replace "'", "''"
        $Filter = "PartitionKey eq 'AppConsentBlockedDelta' and RowKey eq '{0}'" -f $EscapedTenant
        $PreviousRow = Get-CIPPAzDataTableEntity @DeltaTable -Filter $Filter

        $SeenApps = @{}
        if ($PreviousRow.delta) {
            foreach ($Id in @($PreviousRow.delta | ConvertFrom-Json -ErrorAction SilentlyContinue)) {
                if ($Id) { $SeenApps[[string]$Id] = $true }
            }
        }

        $NewAppIds = @($Blocked.Keys | Where-Object { -not $SeenApps.ContainsKey($_) })

        # Record everything seen this cycle BEFORE deciding what to surface, so a suppressed item
        # is never re-surfaced later.
        $AllSeen = @(@($SeenApps.Keys) + @($Blocked.Keys) | Sort-Object -Unique)
        Add-CIPPAzDataTableEntity @DeltaTable -Entity @{
            PartitionKey = 'AppConsentBlockedDelta'
            RowKey       = [string]$TenantFilter
            delta        = [string](ConvertTo-Json -InputObject $AllSeen -Compress)
        } -Force

        # Back-fill mode: the first run on a tenant establishes the baseline and surfaces nothing.
        # Without this, enabling the alert replays the entire retained sign-in history across every
        # tenant into the ticket queue in one cycle.
        if (-not $PreviousRow) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "App consent alert: baseline established for $($AllSeen.Count) application(s); nothing surfaced on first run." -sev Info
            return
        }

        if ($NewAppIds.Count -eq 0) { return }

        $Surfaced = @($NewAppIds | Select-Object -First $MaxSurfacedPerCycle)
        if ($NewAppIds.Count -gt $MaxSurfacedPerCycle) {
            # Suppression is never silent - a swallowed burst looks identical to a working alert.
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "App consent alert: $($NewAppIds.Count) newly blocked applications exceeded the per-cycle cap of $MaxSurfacedPerCycle; surfaced $($Surfaced.Count). The remainder are recorded as seen and will not re-surface." -sev Warning
        }

        $AlertData = foreach ($AppId in $Surfaced) {
            $Info = $Blocked[$AppId]
            $ConsentUrl = if ($CustomerId) { "https://login.microsoftonline.com/$CustomerId/adminconsent?client_id=$AppId" } else { 'unavailable - could not resolve tenant id' }
            [PSCustomObject]@{
                'Application'   = $Info.AppName
                'Application Id' = $Info.AppId
                'Resource'      = $Info.Resource
                'Users Blocked' = $Info.Users.Count
                'Users'         = (@($Info.Users) | Sort-Object) -join ', '
                'Error Codes'   = (@($Info.ErrorCodes) | Sort-Object) -join ', '
                'Attempts'      = $Info.Count
                'First Seen'    = $Info.FirstSeen.ToString('u')
                'Last Seen'     = $Info.LastSeen.ToString('u')
                'Admin Consent URL' = $ConsentUrl
                'Tenant'        = $TenantFilter
            }
        }

        Write-AlertTrace -cmdletName $MyInvocation.MyCommand -tenantFilter $TenantFilter -data $AlertData
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Could not check for blocked app consent for $($TenantFilter): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
    }
}
