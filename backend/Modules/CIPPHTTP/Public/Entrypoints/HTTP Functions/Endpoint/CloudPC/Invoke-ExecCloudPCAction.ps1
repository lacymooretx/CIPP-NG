using namespace System.Net

function Invoke-ExecCloudPCAction {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    .DESCRIPTION
        Runs a lifecycle action against a single Windows 365 Cloud PC.

        Three of these destroy data and one deletes the machine:

          reprovision     rebuilds the Cloud PC from its policy image. THE LOCAL DISK IS WIPED.
                          Anything not in OneDrive, a roaming profile or the user's mailbox is gone.
          endGracePeriod  ends the grace period immediately, which DEPROVISIONS the Cloud PC.
                          This is a deletion, not a pause.
          restore         rolls back to a snapshot. Everything written since that snapshot is lost.
          resize          moves the Cloud PC to a different SKU. User data is retained, but the
                          machine restarts and is unavailable while it happens.

        Protections, deliberately awkward in proportion to what the action does:

        1. ONE Cloud PC per call. CloudPcId must be a single id - an array is refused outright.
           There is no bulk reprovision here and that is on purpose: the blast radius of getting a
           filter wrong is every desk in the tenant.
        2. The three destructive actions require ConfirmText to EXACTLY match the Cloud PC's own
           displayName. Not a checkbox, not "yes" - the name of the specific machine, which means
           the operator had to read the row they are about to destroy. The name is fetched from
           Graph, not taken from the caller, so a stale UI cannot satisfy it.
        3. resize requires Confirm=true plus a TargetServicePlanId.
        4. The Cloud PC's state before the action is written to the audit log, because after a
           reprovision there is nothing left to tell you what was there.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $TenantFilter = $Request.Body.tenantFilter ?? $Request.Query.tenantFilter
    $CloudPcIdRaw = $Request.Body.CloudPcId ?? $Request.Query.CloudPcId
    $Action = "$($Request.Body.Action ?? $Request.Query.Action)"
    $ConfirmText = "$($Request.Body.ConfirmText)"
    $Confirm = ConvertTo-CIPPBoolean -Value $Request.Body.Confirm
    $SnapshotId = $Request.Body.SnapshotId
    $TargetServicePlanId = $Request.Body.TargetServicePlanId

    # Actions that cannot be undone. Kept as data so the guard below cannot drift from the list.
    $DestructiveActions = @('reprovision', 'endGracePeriod', 'restore')
    $ValidActions = @('reprovision', 'endGracePeriod', 'restore', 'resize', 'troubleshoot')

    try {
        if ([string]::IsNullOrWhiteSpace($TenantFilter)) { throw 'tenantFilter is required.' }

        # (1) Single target only. An array here would be a bulk destructive action.
        if ($CloudPcIdRaw -is [array] -or $CloudPcIdRaw -is [System.Collections.IEnumerable] -and $CloudPcIdRaw -isnot [string]) {
            throw 'CloudPcId must be a single Cloud PC id. This endpoint deliberately does not accept a list - run one Cloud PC at a time.'
        }
        $CloudPcId = "$CloudPcIdRaw"
        if ([string]::IsNullOrWhiteSpace($CloudPcId)) { throw 'CloudPcId is required.' }
        if ($Action -notin $ValidActions) {
            throw "Invalid Action '$Action'. Allowed: $($ValidActions -join ', ')."
        }

        # Read the Cloud PC first: proves it exists, gives the name the confirmation must match,
        # and captures the state that will not survive the action.
        $CloudPC = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs/$CloudPcId" -tenantid $TenantFilter -AsApp $true -ErrorAction Stop
        if (-not $CloudPC -or -not $CloudPC.id) { throw "Cloud PC $CloudPcId was not found in this tenant." }

        $Describe = "'$($CloudPC.displayName)' ($($CloudPC.userPrincipalName), $($CloudPC.servicePlanName), status $($CloudPC.status))"

        # (2) Typed confirmation for anything that destroys data.
        if ($Action -in $DestructiveActions) {
            if ($ConfirmText -cne "$($CloudPC.displayName)") {
                throw "$Action is destructive and was not confirmed. To proceed, resend with ConfirmText set to the Cloud PC's exact display name: '$($CloudPC.displayName)'. This one belongs to $($CloudPC.userPrincipalName)."
            }
        }

        $Uri = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs/$CloudPcId/$Action"
        $ActionBody = $null

        switch ($Action) {
            'restore' {
                if ([string]::IsNullOrWhiteSpace($SnapshotId)) {
                    throw 'restore requires SnapshotId. Snapshots are listed in the Intune portal under the Cloud PC; CIPP does not enumerate them.'
                }
                $ActionBody = @{ cloudPcSnapshotId = $SnapshotId } | ConvertTo-Json -Compress
            }
            'resize' {
                if ([string]::IsNullOrWhiteSpace($TargetServicePlanId)) {
                    throw 'resize requires TargetServicePlanId. Use ListCloudPCGalleryImages'' sibling data or the servicePlans catalogue for a valid id.'
                }
                if (-not $Confirm) {
                    throw "resize restarts the Cloud PC and it is unavailable while it happens. Resend with Confirm=true to proceed. Target: $Describe."
                }
                $ActionBody = @{ targetServicePlanId = $TargetServicePlanId } | ConvertTo-Json -Compress
            }
            default { $ActionBody = '{}' }
        }

        # (4) Record what was there BEFORE, at Warn for the destructive ones so it stands out.
        $Severity = if ($Action -in $DestructiveActions) { 'Warn' } else { 'Info' }
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Cloud PC $Action requested on $Describe [id $CloudPcId, device $($CloudPC.managedDeviceName), policy $($CloudPC.provisioningPolicyName)]" -Sev $Severity

        $null = New-GraphPOSTRequest -uri $Uri -tenantid $TenantFilter -body $ActionBody -AsApp $true -ErrorAction Stop

        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Cloud PC $Action accepted for $Describe" -Sev $Severity

        $Note = switch ($Action) {
            'reprovision' { 'The Cloud PC is being rebuilt from its policy image. The previous local disk is gone.' }
            'endGracePeriod' { 'The grace period has ended and the Cloud PC is being deprovisioned.' }
            'restore' { 'The Cloud PC is being restored to the selected snapshot. Changes made after that snapshot are gone.' }
            'resize' { 'The Cloud PC is resizing and will restart. User data is retained.' }
            default { 'Action accepted.' }
        }

        $Body = [PSCustomObject]@{
            Results = "$Action accepted for $($CloudPC.displayName). $Note Graph accepts these asynchronously - re-read the Cloud PC to watch its status change."
            CloudPcId = $CloudPcId
            Action    = $Action
            PreviousState = [PSCustomObject]@{
                displayName       = $CloudPC.displayName
                userPrincipalName = $CloudPC.userPrincipalName
                servicePlanName   = $CloudPC.servicePlanName
                status            = $CloudPC.status
                managedDeviceName = $CloudPC.managedDeviceName
            }
        }
        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Cloud PC $Action failed: $($ErrorMessage.NormalizedError)" -Sev Error -LogData $ErrorMessage
        $Body = [PSCustomObject]@{ Results = "Failed to run $Action : $($ErrorMessage.NormalizedError)" }
        $StatusCode = [HttpStatusCode]::BadRequest
    }

    return ([HttpResponseContext]@{ StatusCode = $StatusCode; Body = $Body })
}
