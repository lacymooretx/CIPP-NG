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

        Guards against re-ticketing, added after this alert was found to re-fire on every run for as
        long as a request stayed pending:
          - a delta baseline keyed on the user consent request id, so each request is reported once
          - back-fill mode, so the first run on a tenant records a baseline and surfaces nothing
          - a per-cycle cap, with the excess still recorded as seen so it cannot arrive later
        These mirror the ControlR ingest flood (tickets #57308-#57357), where replaying an
        unprocessed backlog in one cycle opened 50 tickets at once.
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
        if ($Approvals.Count -eq 0) { return }

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

        $Pending = [System.Collections.Generic.List[object]]::new()
        foreach ($App in $Approvals) {
            try {
                $UserConsentRequests = @(New-GraphGetRequest -Uri "https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests/$($App.id)/userConsentRequests" -tenantid $TenantFilter)
            } catch {
                # One unreadable request must not discard the rest.
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

        if ($Pending.Count -eq 0) { return }

        # Baseline of every request id ever surfaced, append-only. Keyed on the USER consent request
        # id rather than the app, so a second person requesting the same app is still reported.
        $DeltaTable = Get-CIPPTable -Table DeltaCompare
        $EscapedTenant = $TenantFilter -replace "'", "''"
        $Filter = "PartitionKey eq 'AppApprovalDelta' and RowKey eq '{0}'" -f $EscapedTenant
        $PreviousRow = Get-CIPPAzDataTableEntity @DeltaTable -Filter $Filter

        $SeenRequests = @{}
        if ($PreviousRow.delta) {
            foreach ($Id in @($PreviousRow.delta | ConvertFrom-Json -ErrorAction SilentlyContinue)) {
                if ($Id) { $SeenRequests[[string]$Id] = $true }
            }
        }

        $NewRequests = @($Pending | Where-Object { -not $SeenRequests.ContainsKey($_.RequestId) })

        # Record everything seen this cycle BEFORE deciding what to surface, so a suppressed item is
        # never re-surfaced later.
        $AllSeen = @(@($SeenRequests.Keys) + @($Pending.RequestId) | Sort-Object -Unique)
        Add-CIPPAzDataTableEntity @DeltaTable -Entity @{
            PartitionKey = 'AppApprovalDelta'
            RowKey       = [string]$TenantFilter
            delta        = [string](ConvertTo-Json -InputObject $AllSeen -Compress)
        } -Force

        if (-not $PreviousRow) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "App approval alert: baseline established for $($AllSeen.Count) pending request(s); nothing surfaced on first run." -sev Info
            return
        }

        if ($NewRequests.Count -eq 0) { return }

        $Surfaced = @($NewRequests | Select-Object -First $MaxSurfacedPerCycle)
        if ($NewRequests.Count -gt $MaxSurfacedPerCycle) {
            Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "App approval alert: $($NewRequests.Count) new pending requests exceeded the per-cycle cap of $MaxSurfacedPerCycle; surfaced $($Surfaced.Count). The remainder are recorded as seen and will not re-surface." -sev Warning
        }

        Write-AlertTrace -cmdletName $MyInvocation.MyCommand -tenantFilter $TenantFilter -data $Surfaced
    } catch {
        # Previously an empty catch, which hid every failure including a broken query.
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Could not check pending app consent requests for $($TenantFilter): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
    }
}
