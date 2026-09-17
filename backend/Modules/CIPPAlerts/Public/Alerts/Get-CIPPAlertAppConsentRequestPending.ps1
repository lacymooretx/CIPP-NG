function Get-CIPPAlertAppConsentRequestPending {
    <#
    .SYNOPSIS
        Alert on app consent requests waiting for an administrator to review
    .DESCRIPTION
        Where a tenant has the admin consent request workflow enabled, users who are blocked from an
        app can submit a request with a business justification. Those requests queue in the portal
        under Enterprise applications > Admin consent requests - and are only noticed if somebody
        goes and looks, or if a reviewer receives Microsoft's notification email.

        Neither reliably happens here. Reviewers must hold a role that can consent, and on several
        tenants the only such accounts are unlicensed with no mailbox, so the notification has
        nowhere to land. The observable consequence: on aspendora.com - the one tenant with the
        workflow enabled - a request sat unreviewed until it reached status 'Expired'.

        This alert makes the queue visible as a ticket instead. Only 'InProgress' requests are
        surfaced, because those are the ones an administrator can still act on.

        Companion to Get-CIPPAlertAppConsentBlocked, which catches the same demand from the sign-in
        log on the ~7 of 8 tenants where this workflow is switched off entirely. This one adds the
        user's own justification, which the sign-in log does not carry.
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

    $MaxSurfacedPerCycle = if ($InputValue.AppConsentRequestMaxPerCycle) { [int]$InputValue.AppConsentRequestMaxPerCycle } else { 10 }
    # Each consent request needs its own child call for status and requester, so the work is N+1 in
    # the number of requests. Bounded so a tenant with a long history cannot stall the alert cycle.
    $MaxRequestsInspected = if ($InputValue.AppConsentRequestMaxInspected) { [int]$InputValue.AppConsentRequestMaxInspected } else { 50 }

    try {
        # A tenant with the workflow disabled simply has nothing here. That is the normal case, not
        # an error, so it must not log noise on every cycle for every such tenant.
        $Requests = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/identityGovernance/appConsent/appConsentRequests' -tenantid $TenantFilter -ErrorAction Stop)
        if ($Requests.Count -eq 0) { return }

        $CustomerId = $null
        try { $CustomerId = (Get-Tenants -TenantFilter $TenantFilter).customerId } catch {}

        $Pending = [System.Collections.Generic.List[object]]::new()
        foreach ($Request in ($Requests | Select-Object -First $MaxRequestsInspected)) {
            # The inline userConsentRequests collection comes back empty; status, requester and the
            # justification only exist on the child collection, so it has to be fetched per request.
            try {
                $UserRequests = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests/$($Request.id)/userConsentRequests" -tenantid $TenantFilter -ErrorAction Stop)
            } catch {
                # One unreadable request must not discard the others.
                Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "App consent request alert: could not read user requests for '$($Request.appDisplayName)'." -sev Info
                continue
            }

            foreach ($UserRequest in $UserRequests) {
                if ($UserRequest.status -ne 'InProgress') { continue }
                $Pending.Add([PSCustomObject]@{
                        RequestId = [string]$UserRequest.id
                        AppId     = [string]$Request.appId
                        AppName   = [string]$Request.appDisplayName
                        Scopes    = (@($Request.pendingScopes.displayName) | Where-Object { $_ }) -join ', '
                        Requester = [string]$UserRequest.createdBy.user.userPrincipalName
                        Reason    = [string]$UserRequest.reason
                        Created   = $UserRequest.createdDateTime
                    })
            }
        }

        if ($Pending.Count -eq 0) { return }

        # Baseline of every request id ever surfaced, append-only. Keyed on the user consent request
        # id rather than the app, so a second person requesting the same app is still reported.
        $DeltaTable = Get-CIPPTable -Table DeltaCompare
        $EscapedTenant = $TenantFilter -replace "'", "''"
        $Filter = "PartitionKey eq 'AppConsentRequestDelta' and RowKey eq '{0}'" -f $EscapedTenant
        $PreviousRow = Get-CIPPAzDataTableEntity @DeltaTable -Filter $Filter

        $SeenRequests = @{}
        if ($PreviousRow.delta) {
            foreach ($Id in @($PreviousRow.delta | ConvertFrom-Json -ErrorAction SilentlyContinue)) {
                if ($Id) { $SeenRequests[[string]$Id] = $true }
            }
        }

        $NewRequests = @($Pending | Where-Object { -not $SeenRequests.ContainsKey($_.RequestId) })

        $AllSeen = @(@($SeenRequests.Keys) + @($Pending.RequestId) | Sort-Object -Unique)
        Add-CIPPAzDataTableEntity @DeltaTable -Entity @{
            PartitionKey = 'AppConsentRequestDelta'
            RowKey       = [string]$TenantFilter
            delta        = [string](ConvertTo-Json -InputObject $AllSeen -Compress)
        } -Force

        # First run establishes the baseline silently, for the same reason as the blocked-consent
        # alert: a tenant with a backlog would otherwise ticket the whole queue at once.
        if (-not $PreviousRow) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "App consent request alert: baseline established for $($AllSeen.Count) pending request(s); nothing surfaced on first run." -sev Info
            return
        }

        if ($NewRequests.Count -eq 0) { return }

        $Surfaced = @($NewRequests | Select-Object -First $MaxSurfacedPerCycle)
        if ($NewRequests.Count -gt $MaxSurfacedPerCycle) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "App consent request alert: $($NewRequests.Count) new pending requests exceeded the per-cycle cap of $MaxSurfacedPerCycle; surfaced $($Surfaced.Count). The remainder are recorded as seen and will not re-surface." -sev Warning
        }

        $AlertData = foreach ($Item in $Surfaced) {
            [PSCustomObject]@{
                'Application'       = $Item.AppName
                'Application Id'    = $Item.AppId
                'Requested By'      = $Item.Requester
                'Justification'     = $Item.Reason
                'Permissions'       = $Item.Scopes
                'Requested'         = if ($Item.Created) { ([datetime]$Item.Created).ToUniversalTime().ToString('u') } else { '' }
                'Admin Consent URL' = if ($CustomerId) { "https://login.microsoftonline.com/$CustomerId/adminconsent?client_id=$($Item.AppId)" } else { 'unavailable - could not resolve tenant id' }
                'Tenant'            = $TenantFilter
            }
        }

        Write-AlertTrace -cmdletName $MyInvocation.MyCommand -tenantFilter $TenantFilter -data $AlertData
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Could not check pending app consent requests for $($TenantFilter): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
    }
}
