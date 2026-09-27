function Get-CIPPAlertNewAppApproval {
    <#
    .SYNOPSIS
        Alert on app consent requests waiting for an administrator to review
    .DESCRIPTION
        Surfaces pending admin consent requests as a ticket, so they are not left sitting in a portal
        queue nobody watches. Observed consequence of that queue being unwatched: on aspendora.com a
        real request reached status 'Expired' without ever being reviewed.

        The alert carries two ways to act, because Microsoft provides NO API to approve or deny an
        admin consent request (see the consent requests overview in Graph docs - "there aren't any
        methods available to programmatically approve or deny a request"). The documented mechanism
        is to rebuild a consent URL, which both grants consent AND resolves the request:
          - ConsentURL: the admin consent dialog for this exact request. The bf_id parameter ties the
            grant back to the request so Entra marks it approved; without it the grant succeeds but
            the request stays InProgress until it expires.
          - CippURL: the CIPP App Consent Requests page, which lists every pending request for the
            tenant with the same one-click "Approve in Entra" action.

        Re-ticketing is handled by the AlertLifecycle (CIPP 11.0): every successful run reconciles the
        FULL set of pending requests, keyed on the user consent request id (the item's Id), so each
        request notifies once, a second person requesting the same app is still reported, and a
        request that is approved/denied/expires resolves. This replaced the fork's own DeltaCompare
        baseline; Initialize-CIPPAlertLifecycleBaseline hands that baseline over once, so requests
        that were already known are not ticketed again, and a never-baselined tenant still surfaces
        nothing on its first run.

        A per-cycle cap on NEW notifications remains as a flood backstop; the excess is recorded as
        Open by the reconcile, so it cannot arrive later. This mirrors the ControlR ingest flood
        (tickets #57308-#57357), where replaying an unprocessed backlog opened 50 tickets at once.

        If some requests cannot be read, the run reconciles with -Append so unread requests are not
        wrongly resolved (and then re-notified when they are read again).
    .FUNCTIONALITY
        Entrypoint
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [Alias('input')]
        $InputValue,
        $TenantFilter,
        $Headers
    )

    $MaxSurfacedPerCycle = if ($InputValue.AppApprovalMaxPerCycle) { [int]$InputValue.AppApprovalMaxPerCycle } else { 10 }

    try {
        $Approvals = @(New-GraphGetRequest -Uri "https://graph.microsoft.com/beta/identityGovernance/appConsent/appConsentRequests?`$top=100&`$filter=userConsentRequests/any(u:u/status eq 'InProgress')" -tenantid $TenantFilter)

        $Pending = [System.Collections.Generic.List[object]]::new()
        $Partial = $false
        if ($Approvals.Count -gt 0) {
            $TenantGUID = (Get-Tenants -TenantFilter $TenantFilter -SkipDomains).customerId

            # Deep link to the CIPP page that lists these, so the ticket offers the queue as well as the
            # single request. Degrades to an empty string rather than failing the alert.
            $CippUrl = ''
            try {
                $CippConfigTable = Get-CIPPTable -tablename 'Config'
                $CippConfig = Get-CIPPAzDataTableEntity @CippConfigTable -Filter "PartitionKey eq 'InstanceProperties' and RowKey eq 'CIPPURL'"
                if ($CippConfig.Value) {
                    $CippUrl = 'https://{0}/tenant/administration/app-consent-requests?tenantFilter={1}' -f $CippConfig.Value, $TenantFilter
                }
            } catch {}

            foreach ($App in $Approvals) {
                try {
                    $UserConsentRequests = @(New-GraphGetRequest -Uri "https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests/$($App.id)/userConsentRequests" -tenantid $TenantFilter)
                } catch {
                    # One unreadable request must not discard the rest.
                    $Partial = $true
                    Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "App approval alert: could not read user requests for '$($App.appDisplayName)'." -sev Info
                    continue
                }

                $ConsentUrl = if ($App.consentType -eq 'Static') {
                    # if something is going wrong here you've probably stumbled on a fourth variation - rvdwegen
                    "https://login.microsoftonline.com/$($TenantFilter)/adminConsent?client_id=$($App.appId)&bf_id=$($App.id)&redirect_uri=https://entra.microsoft.com/TokenAuthorize"
                } elseif ($App.pendingScopes.displayName) {
                    "https://login.microsoftonline.com/$($TenantFilter)/v2.0/adminConsent?client_id=$($App.appId)&scope=$($App.pendingScopes.displayName -Join(' '))&bf_id=$($App.id)&redirect_uri=https://entra.microsoft.com/TokenAuthorize"
                } else {
                    "https://login.microsoftonline.com/$($TenantFilter)/adminConsent?client_id=$($App.appId)&bf_id=$($App.id)&redirect_uri=https://entra.microsoft.com/TokenAuthorize"
                }

                foreach ($UserRequest in $UserConsentRequests) {
                    # The top-level filter matches an app when ANY of its userConsentRequests is
                    # InProgress, but this per-app list returns ALL of them - including Completed, Denied
                    # and Expired - so without this guard already-resolved requests were alerted on.
                    if ($UserRequest.status -ne 'InProgress') { continue }

                    $Pending.Add([PSCustomObject]@{
                            # Lifecycle identity (Get-AlertContentHash keys on Id): one row per user request.
                            Id          = [string]$UserRequest.id
                            RequestId   = [string]$UserRequest.id
                            AppName     = [string]$App.appDisplayName
                            RequestUser = [string]$UserRequest.createdBy.user.userPrincipalName
                            Reason      = [string]$UserRequest.reason
                            RequestDate = $UserRequest.createdDateTime
                            Status      = [string]$UserRequest.status
                            AppId       = [string]$App.appId
                            Scopes      = ($App.pendingScopes.displayName -join ', ')
                            ConsentURL  = $ConsentUrl
                            CippURL     = $CippUrl
                            Tenant      = $TenantFilter
                            TenantId    = $TenantGUID
                        })
                }
            }
        }

        $CmdletName = [string]$MyInvocation.MyCommand
        Initialize-CIPPAlertLifecycleBaseline -CmdletName $CmdletName -TenantFilter $TenantFilter `
            -BaselinePartition 'AppApprovalDelta' -CurrentItems @($Pending) `
            -KnownItemsFromBaseline { param($Ids) foreach ($Id in $Ids) { @{ Id = [string]$Id } } }

        # Every successful run reconciles, including an empty one, so approved/denied/expired
        # requests resolve. A partial read appends instead of resolving what it could not see.
        $New = @(Write-AlertTrace -cmdletName $CmdletName -tenantFilter $TenantFilter -data @($Pending) -Append:$Partial | Where-Object { $_ })
        if ($New.Count -eq 0) { return }

        if ($New.Count -gt $MaxSurfacedPerCycle) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "App approval alert: $($New.Count) new pending requests exceeded the per-cycle cap of $MaxSurfacedPerCycle; surfaced $MaxSurfacedPerCycle. The remainder are recorded as open and will not re-surface." -sev Warning
        }
        $New | Select-Object -First $MaxSurfacedPerCycle
    } catch {
        # Previously an empty catch, which hid every failure including a broken query.
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Could not check pending app consent requests for $($TenantFilter): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
    }
}
