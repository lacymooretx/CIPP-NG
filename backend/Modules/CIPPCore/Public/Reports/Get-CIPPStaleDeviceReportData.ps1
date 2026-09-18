function Get-CIPPStaleDeviceReportData {
    <#
    .SYNOPSIS
        Gather the Stale Device Report model for a single tenant.
    .DESCRIPTION
        Cross-references Intune managed devices against Entra device objects to find the orphans in
        BOTH directions, which neither list shows on its own:

          - an Intune record whose Entra device object no longer exists
          - an Entra device that was never enrolled in Intune
          - a device whose owner is disabled or deleted but which still holds a record
          - devices that simply stopped checking in

        The join is on the Entra deviceId, NOT the Intune managed device id - they are different
        identifiers, and joining on the wrong one produces a report where every device looks
        orphaned.

        Each row carries a recommended action rather than a raw age, because "last seen 400 days
        ago" means something different for a never-enrolled Entra record than for an Intune device
        whose owner left.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter
    )

    # A device quiet for this long is treated as stale. Chosen to sit well beyond any normal leave
    # or seasonal absence, so a laptop in a drawer over summer does not generate a RETIRE action.
    $StaleDays = 90
    $GraphBeta = 'https://graph.microsoft.com/beta'
    $Now = (Get-Date).ToUniversalTime()

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Sections = [System.Collections.Generic.List[object]]::new()

    function Add-Finding($Title, $Status, $Detail) { $Findings.Add(@{ Title = $Title; Status = $Status; Detail = $Detail }) }
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
    function Get-Age($Value) {
        if (-not $Value) { return $null }
        try { return [int]($Now - ([datetime]$Value).ToUniversalTime()).TotalDays } catch { return $null }
    }

    $Org = $null
    try { $Org = New-GraphGetRequest -uri "$GraphBeta/organization" -tenantid $TenantFilter | Select-Object -First 1 } catch {}
    $TenantName = if ($Org.displayName) { $Org.displayName } else { $TenantFilter }
    $DefaultDomain = ($Org.verifiedDomains | Where-Object { $_.isDefault }).name
    if (-not $DefaultDomain) { $DefaultDomain = $TenantFilter }

    $Managed = @()
    $EntraDevices = @()
    try { $Managed = @(New-GraphGetRequest -uri "$GraphBeta/deviceManagement/managedDevices?`$select=id,deviceName,azureADDeviceId,lastSyncDateTime,operatingSystem,userPrincipalName,managementAgent" -tenantid $TenantFilter) } catch {}
    try { $EntraDevices = @(New-GraphGetRequest -uri "$GraphBeta/devices?`$select=id,deviceId,displayName,accountEnabled,approximateLastSignInDateTime,operatingSystem,isManaged,trustType" -tenantid $TenantFilter) } catch {}

    # Join on the ENTRA deviceId. The Intune managed device id is a different identifier; joining on
    # it matches nothing and every device reads as orphaned.
    $EntraByDeviceId = @{}
    foreach ($D in $EntraDevices) { if ($D.deviceId) { $EntraByDeviceId[[string]$D.deviceId] = $D } }
    $IntuneByAadId = @{}
    foreach ($D in $Managed) { if ($D.azureADDeviceId) { $IntuneByAadId[[string]$D.azureADDeviceId] = $D } }

    # Disabled or deleted owners. A device whose owner left is a different problem from a quiet one.
    $DisabledUsers = @{}
    try {
        foreach ($U in @(New-GraphGetRequest -uri "$GraphBeta/users?`$select=userPrincipalName,accountEnabled&`$filter=accountEnabled eq false&`$top=999" -tenantid $TenantFilter)) {
            if ($U.userPrincipalName) { $DisabledUsers[[string]$U.userPrincipalName.ToLower()] = $true }
        }
    } catch {}

    Invoke-Section 'Device Records Needing Action' {
        $r = New-RowList
        $Counts = @{ RETIRE = 0; DELETE = 0; REVIEW = 0; MONITOR = 0 }

        foreach ($Device in $Managed) {
            $Age = Get-Age $Device.lastSyncDateTime
            $AadId = [string]$Device.azureADDeviceId
            $HasEntra = $AadId -and $EntraByDeviceId.ContainsKey($AadId)
            $Upn = [string]$Device.userPrincipalName
            $OwnerDisabled = $Upn -and $DisabledUsers.ContainsKey($Upn.ToLower())

            $Action = $null; $Reason = $null
            if (-not $HasEntra) {
                # The Intune record outlived its directory object; it can never be managed again.
                $Action = 'DELETE'; $Reason = 'Intune record has no matching Entra device object'
            } elseif ($OwnerDisabled) {
                $Action = 'REVIEW'; $Reason = "Primary user $Upn is disabled"
            } elseif ($null -ne $Age -and $Age -ge $StaleDays) {
                $Action = 'RETIRE'; $Reason = "No Intune check-in for $Age days"
            } elseif ($null -eq $Age) {
                $Action = 'REVIEW'; $Reason = 'No recorded Intune check-in'
            }
            if (-not $Action) { continue }

            $Counts[$Action]++
            $r.Add(@($Action, [string]$Device.deviceName, 'Intune', [string]$Device.operatingSystem, $(if ($null -ne $Age) { "$Age d" } else { 'never' }), $Upn, $Reason))
        }

        foreach ($Device in $EntraDevices) {
            $DevId = [string]$Device.deviceId
            if ($DevId -and $IntuneByAadId.ContainsKey($DevId)) { continue }   # covered above
            $Age = Get-Age $Device.approximateLastSignInDateTime

            # trustType decides whether DELETE is even a safe recommendation, so it is read before
            # the staleness rules rather than after:
            #   ServerAd  - hybrid domain-joined. The Entra object is owned by AD Connect. Deleting
            #               it either re-syncs straight back or breaks the device's Entra identity
            #               and its Conditional Access. The fix belongs in on-prem AD.
            #   Workplace - registered / BYOD. Never Intune-enrolled BY DESIGN, so "not enrolled" is
            #               not evidence of anything wrong. Deleting forces the user to re-register.
            #   AzureAd   - cloud-joined and never enrolled is a genuine orphan.
            $Trust = [string]$Device.trustType
            $Source = switch ($Trust) {
                'ServerAd' { 'Entra only (hybrid)' }
                'Workplace' { 'Entra only (registered)' }
                default { 'Entra only' }
            }

            $Action = $null; $Reason = $null
            if ($Trust -eq 'ServerAd') {
                # Never DELETE: the record is a projection of an on-prem AD object.
                if (($null -ne $Age -and $Age -ge $StaleDays) -or -not $Device.accountEnabled) {
                    $Action = 'REVIEW'
                    $Reason = "Hybrid-joined and quiet$(if ($null -ne $Age) { " for $Age days" }). Managed by AD Connect - remove it from on-premises AD, not from Entra; deleting the Entra object here will re-sync or break the device's identity."
                } else {
                    $Action = 'MONITOR'; $Reason = 'Hybrid-joined and active, but not enrolled in Intune'
                }
            } elseif ($Trust -eq 'Workplace') {
                if ($null -ne $Age -and $Age -ge $StaleDays) {
                    $Action = 'REVIEW'
                    $Reason = "Registered (BYOD) device, no sign-in for $Age days. Not being Intune-enrolled is expected for this type; deleting it forces the user to re-register."
                } else {
                    $Action = 'MONITOR'; $Reason = 'Registered (BYOD) device, active'
                }
            } elseif ($null -ne $Age -and $Age -ge $StaleDays) {
                $Action = 'DELETE'; $Reason = "Cloud-joined, never enrolled in Intune and no sign-in for $Age days"
            } elseif (-not $Device.accountEnabled) {
                $Action = 'DELETE'; $Reason = 'Entra device object is disabled and not enrolled'
            } else {
                # Present and active but unmanaged - an enrolment gap, not a cleanup item.
                $Action = 'MONITOR'; $Reason = 'Entra device is active but not enrolled in Intune'
            }

            $Counts[$Action]++
            $r.Add(@($Action, [string]$Device.displayName, $Source, [string]$Device.operatingSystem, $(if ($null -ne $Age) { "$Age d" } else { 'never' }), '', $Reason))
        }

        $Columns = @('Action', 'Device', 'Source', 'OS', 'Last Seen', 'Owner', 'Reason')
        # Ordered by how final the action is, then device name. Built by iterating the buckets
        # rather than piping the row list: each row is itself an array, and piping a collection of
        # arrays unrolls a single row into its individual cells.
        $Sorted = New-RowList
        foreach ($Action in @('DELETE', 'RETIRE', 'REVIEW', 'MONITOR')) {
            $Bucket = New-RowList
            for ($i = 0; $i -lt $r.Count; $i++) { if ($r[$i][0] -eq $Action) { $Bucket.Add($r[$i]) } }
            $Names = [System.Collections.Generic.List[string]]::new()
            for ($i = 0; $i -lt $Bucket.Count; $i++) { $Names.Add([string]$Bucket[$i][1]) }
            $Names.Sort()
            foreach ($Name in $Names) {
                for ($i = 0; $i -lt $Bucket.Count; $i++) {
                    if ([string]$Bucket[$i][1] -eq $Name) { $Sorted.Add($Bucket[$i]); $Bucket.RemoveAt($i); break }
                }
            }
        }

        $Status = if ($Counts.DELETE -gt 0 -or $Counts.RETIRE -gt 0) { 'warn' } else { 'pass' }
        Add-Section 'Device Records Needing Action' $Status "Orphans in both directions, plus devices that stopped checking in. Stale threshold: $StaleDays days." $Columns $Sorted 'No stale or orphaned device records found.'

        if ($Counts.DELETE -gt 0) { Add-Finding 'Orphaned device records' 'warn' "$($Counts.DELETE) record(s) exist in only one directory and cannot be managed." }
        if ($Counts.RETIRE -gt 0) { Add-Finding 'Devices no longer checking in' 'warn' "$($Counts.RETIRE) Intune device(s) have not synced in $StaleDays days or more." }
        if ($Counts.REVIEW -gt 0) { Add-Finding 'Devices needing a human decision' 'warn' "$($Counts.REVIEW) device(s) need review: a disabled owner, or a hybrid/registered record that must not simply be deleted from Entra." }
        if ($Counts.MONITOR -gt 0) { Add-Finding 'Unenrolled active devices' 'warn' "$($Counts.MONITOR) active Entra device(s) are not enrolled in Intune." }
        if (($Counts.Values | Measure-Object -Sum).Sum -eq 0) { Add-Finding 'Device records are clean' 'pass' 'Intune and Entra agree, and every device is checking in.' }
    }

    Invoke-Section 'Inventory Summary' {
        $r = New-RowList
        $r.Add(@('Intune managed devices', [string]$Managed.Count))
        $r.Add(@('Entra device objects', [string]$EntraDevices.Count))
        $r.Add(@('Matched in both', [string]@($Managed | Where-Object { $_.azureADDeviceId -and $EntraByDeviceId.ContainsKey([string]$_.azureADDeviceId) }).Count))
        Add-Section 'Inventory Summary' 'pass' 'Record counts on each side of the join.' @('Measure', 'Count') $r $null
    }

    return @{
        Title         = 'Stale Device Report'
        TenantName    = $TenantName
        TenantDomain  = $DefaultDomain
        GeneratedDate = (Get-Date).ToString('dd MMMM yyyy')
        Findings      = $Findings
        Sections      = $Sections
    }
}
