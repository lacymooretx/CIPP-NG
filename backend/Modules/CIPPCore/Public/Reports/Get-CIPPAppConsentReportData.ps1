function Get-CIPPAppConsentReportData {
    <#
    .SYNOPSIS
        Gather the App Consent Posture Report model for a single tenant.
    .DESCRIPTION
        Answers, per tenant, the three questions that came out of CW #58402:

          1. Can users even ask? If the admin consent request workflow is off, a blocked user hits a
             dead end with no "ask your admin" button and nobody is told. Surveyed 2026-09-17, this
             was off on 7 of 8 client tenants.
          2. What are users actually being blocked on? Sign-in failures 65001 / 90094 show real
             demand, and are recorded regardless of tenant configuration.
          3. What is queued, and what did we let expire? A request that reaches 'Expired' is one an
             administrator never answered - which happened on the one tenant that had the workflow
             enabled.

        It also reports the user consent tier, because a tenant in Microsoft-managed consent mode
        cannot have that assignment changed through the API at all (the property silently accepts
        writes and discards them - see docs/todo-cipp-bugs.md 5b), so per-app admin consent is the
        only route there.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    $GraphBeta = 'https://graph.microsoft.com/beta'
    $Findings = [System.Collections.Generic.List[object]]::new()
    $Sections = [System.Collections.Generic.List[object]]::new()

    function Add-Finding($Title, $Status, $Detail) {
        $Findings.Add(@{ Title = $Title; Status = $Status; Detail = $Detail })
    }
    function Add-Section($Title, $Status, $Description, $Columns, $Rows, $Empty) {
        $Sections.Add(@{ Title = $Title; Status = $Status; Description = $Description; Columns = $Columns; Rows = $Rows; Empty = $Empty })
    }
    function New-RowList { , [System.Collections.Generic.List[object]]::new() }
    function Invoke-Section($Name, [scriptblock]$Builder) {
        try { & $Builder } catch {
            $r = New-RowList; $r.Add(@("$($_.Exception.Message)"))
            Add-Section $Name 'warn' 'This section could not be retrieved.' @('Error') $r 'Data unavailable.'
        }
    }

    $Org = $null
    try { $Org = New-GraphGetRequest -uri "$GraphBeta/organization" -tenantid $TenantFilter | Select-Object -First 1 } catch {}
    $TenantName = if ($Org.displayName) { $Org.displayName } else { $TenantFilter }
    $DefaultDomain = ($Org.verifiedDomains | Where-Object { $_.isDefault }).name
    if (-not $DefaultDomain) { $DefaultDomain = $TenantFilter }

    $CustomerId = $null
    try { $CustomerId = (Get-Tenants -TenantFilter $TenantFilter).customerId } catch {}

    # ---- Can users ask? -----------------------------------------------------------
    Invoke-Section 'Admin Consent Request Workflow' {
        $Policy = New-GraphGetRequest -uri "$GraphBeta/policies/adminConsentRequestPolicy" -tenantid $TenantFilter
        $Enabled = [bool]$Policy.isEnabled
        $Reviewers = @($Policy.reviewers)
        $r = New-RowList
        $r.Add(@('Request workflow enabled', $(if ($Enabled) { 'Yes' } else { 'No' })))
        $r.Add(@('Notify reviewers by email', $(if ($Policy.notifyReviewers) { 'Yes' } else { 'No' })))
        $r.Add(@('Reviewers configured', [string]$Reviewers.Count))
        $r.Add(@('Request expires after (days)', [string]$Policy.requestDurationInDays))

        if ($Enabled) {
            Add-Section 'Admin Consent Request Workflow' 'pass' 'Blocked users can submit a request with a business justification.' @('Setting', 'Value') $r $null
            if ($Reviewers.Count -eq 0) {
                Add-Finding 'Consent requests have no reviewers' 'warn' 'The request workflow is on but no reviewer is configured, so requests queue with nobody assigned to them.'
            }
        } else {
            Add-Section 'Admin Consent Request Workflow' 'fail' 'Blocked users get no "ask your admin" option - the sign-in simply fails.' @('Setting', 'Value') $r $null
            Add-Finding 'Users cannot request admin consent' 'fail' "Blocked users reach a dead end with no way to ask. Consent demand for this tenant is only visible through the blocked sign-ins below."
        }
    }

    # ---- What tier is user consent on? --------------------------------------------
    Invoke-Section 'User Consent Policy' {
        $Auth = New-GraphGetRequest -uri "$GraphBeta/policies/authorizationPolicy" -tenantid $TenantFilter
        $Assigned = @($Auth.permissionGrantPolicyIdsAssignedToDefaultUserRole)
        $r = New-RowList
        if ($Assigned.Count -eq 0) { $r.Add(@('(none - user consent disabled)')) }
        foreach ($Id in ($Assigned | Sort-Object)) { $r.Add(@([string]$Id)) }

        # The pair below is the fingerprint of "Let Microsoft manage your consent settings".
        $Managed = ($Assigned -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-recommended') -and
                   ($Assigned -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps')

        if ($Managed) {
            Add-Section 'User Consent Policy' 'warn' 'Microsoft-managed consent mode.' @('Assigned permission grant policy') $r $null
            Add-Finding 'Consent settings are Microsoft-managed' 'warn' 'Microsoft controls the consent tier on this tenant. The assignment is read-only through the API - writes return success and change nothing - so a blocked app must be resolved with per-app admin consent rather than by widening user consent.'
        } else {
            Add-Section 'User Consent Policy' 'pass' 'Explicitly configured consent tier.' @('Assigned permission grant policy') $r $null
        }
    }

    # ---- What are users blocked on? -----------------------------------------------
    Invoke-Section 'Blocked Sign-ins (last 30 days)' {
        # Recorded regardless of tenant configuration, which is what makes this the reliable signal.
        # The window is wide for a report; a busy tenant can time out here, and Invoke-Section then
        # degrades this one section rather than the whole report.
        $Cutoff = (Get-Date).ToUniversalTime().AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $Uri = "$GraphBeta/auditLogs/signIns?`$filter=createdDateTime ge $Cutoff and (status/errorCode eq 65001 or status/errorCode eq 90094)&`$select=createdDateTime,userPrincipalName,appDisplayName,appId,status&`$top=200"
        $SignIns = @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter -noPagination $true)

        $ByApp = @{}
        foreach ($s in $SignIns) {
            $Key = [string]$s.appId
            if (-not $Key) { continue }
            if (-not $ByApp.ContainsKey($Key)) {
                $ByApp[$Key] = [pscustomobject]@{
                    Name  = [string]$s.appDisplayName
                    Users = [System.Collections.Generic.HashSet[string]]::new()
                    Count = 0
                    Last  = [datetime]$s.createdDateTime
                }
            }
            $e = $ByApp[$Key]
            if ($s.userPrincipalName) { $null = $e.Users.Add([string]$s.userPrincipalName) }
            $w = [datetime]$s.createdDateTime
            if ($w -gt $e.Last) { $e.Last = $w }
            $e.Count++
        }

        $r = New-RowList
        foreach ($Key in ($ByApp.Keys | Sort-Object { $ByApp[$_].Count } -Descending)) {
            $e = $ByApp[$Key]
            $Url = if ($CustomerId) { "https://login.microsoftonline.com/$CustomerId/adminconsent?client_id=$Key" } else { '' }
            $r.Add(@($e.Name, $Key, [string]$e.Users.Count, [string]$e.Count, $e.Last.ToString('yyyy-MM-dd'), $Url))
        }

        if ($ByApp.Count -gt 0) {
            Add-Section 'Blocked Sign-ins (last 30 days)' 'warn' 'Applications users tried to use and could not, for want of consent. The consent URL grants the app alone, without changing tenant-wide consent settings.' @('Application', 'Application Id', 'Users', 'Attempts', 'Last Seen', 'Admin Consent URL') $r $null
            Add-Finding 'Users are being blocked by consent' 'warn' "$($ByApp.Count) application(s) blocked at least one user in the last 30 days."
        } else {
            Add-Section 'Blocked Sign-ins (last 30 days)' 'pass' 'No consent-blocked sign-ins recorded.' @('Application', 'Application Id', 'Users', 'Attempts', 'Last Seen', 'Admin Consent URL') (New-RowList) 'No users were blocked by consent in the last 30 days.'
        }
    }

    # ---- What is queued, and what expired unanswered? -----------------------------
    Invoke-Section 'Consent Requests' {
        $Requests = @(New-GraphGetRequest -uri "$GraphBeta/identityGovernance/appConsent/appConsentRequests" -tenantid $TenantFilter)
        $r = New-RowList
        $Pending = 0
        $Expired = 0
        foreach ($Request in ($Requests | Select-Object -First 50)) {
            $Children = @()
            try { $Children = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/identityGovernance/appConsent/appConsentRequests/$($Request.id)/userConsentRequests" -tenantid $TenantFilter) } catch { continue }
            foreach ($c in $Children) {
                if ($c.status -eq 'InProgress') { $Pending++ }
                if ($c.status -eq 'Expired') { $Expired++ }
                if ($c.status -notin @('InProgress', 'Expired')) { continue }
                $r.Add(@(
                        [string]$Request.appDisplayName,
                        [string]$c.createdBy.user.userPrincipalName,
                        [string]$c.reason,
                        [string]$c.status,
                        $(if ($c.createdDateTime) { ([datetime]$c.createdDateTime).ToString('yyyy-MM-dd') } else { '' })
                    ))
            }
        }

        $Status = if ($Pending -gt 0) { 'warn' } elseif ($Expired -gt 0) { 'warn' } else { 'pass' }
        Add-Section 'Consent Requests' $Status 'Requests submitted by users, and requests that expired without an answer.' @('Application', 'Requested By', 'Justification', 'Status', 'Requested') $r 'No open or expired consent requests.'

        if ($Pending -gt 0) { Add-Finding 'Consent requests awaiting review' 'warn' "$Pending request(s) are waiting for an administrator." }
        # An expired request is a request somebody made and nobody answered.
        if ($Expired -gt 0) { Add-Finding 'Consent requests expired unanswered' 'warn' "$Expired request(s) expired without ever being reviewed." }
    }

    return @{
        Title         = 'App Consent Posture Report'
        TenantName    = $TenantName
        TenantDomain  = $DefaultDomain
        GeneratedDate = (Get-Date).ToString('dd MMMM yyyy')
        Findings      = $Findings
        Sections      = $Sections
    }
}
