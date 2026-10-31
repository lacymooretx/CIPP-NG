function Get-CIPPIntuneAssignablePolicies {
    <#
    .SYNOPSIS
        Reads every Intune policy family with its assignments, normalised for the effective-policy and hygiene rules.
    .DESCRIPTION
        Policy families come from Get-CIPPIntunePolicyListDefinitions (the same list ListIntunePolicy shows), minus
        App Protection (assigned to users through a different resource). Endpoint security intents have no
        $expand=assignments, so their assignments are read per intent in a second batch. With -IncludeApps,
        assigned apps are read too ($filter=isAssigned eq true keeps that cheap; unassigned apps are never read).
        Assignment filters are returned as a filterId -> @{ displayName; rule; platform } map.
        A family Graph refuses is reported in Errors and skipped; it never fails the whole read.
        Returns @{ Policies; Filters; Errors }. Aspendora fork addition (Vikunja CIPP-19).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [switch]$IncludeApps
    )

    $Errors = [System.Collections.Generic.List[string]]::new()
    $Definitions = @(Get-CIPPIntunePolicyListDefinitions | Where-Object { $_.Id -ne 'ManagedAppPolicies' })
    $Requests = [System.Collections.Generic.List[object]]::new()
    foreach ($D in $Definitions) { $Requests.Add([pscustomobject]@{ id = $D.Id; method = 'GET'; url = $D.GraphUri }) }
    if ($IncludeApps) {
        $Requests.Add([pscustomobject]@{ id = 'MobileApps'; method = 'GET'; url = '/deviceAppManagement/mobileApps?$filter=isAssigned%20eq%20true&$select=id,displayName&$expand=assignments' })
    }
    $Requests.Add([pscustomobject]@{ id = 'AssignmentFilters'; method = 'GET'; url = '/deviceManagement/assignmentFilters?$select=id,displayName,platform,rule' })

    $Results = @(New-GraphBulkRequest -Requests @($Requests) -tenantid $TenantFilter)
    $ById = @{}
    foreach ($R in $Results) { $ById[[string]$R.id] = $R }
    $Ok = {
        param($Id, $Label)
        $R = $ById[$Id]
        if (-not $R) { $Errors.Add("${Label}: no response"); return $false }
        if ($null -ne $R.status -and ($R.status -lt 200 -or $R.status -ge 300)) {
            $Errors.Add("${Label}: HTTP $($R.status) $([string]$R.body.error.message)")
            return $false
        }
        return $true
    }

    $Labels = @{
        DeviceConfigurations = 'Device Configuration'; ConfigurationPolicies = 'Settings Catalog'; GroupPolicyConfigurations = 'Administrative Templates'
        deviceCompliancePolicies = 'Compliance Policy'; Intents = 'Endpoint Security (intent)'; MobileAppConfigurations = 'App Configuration (OEMConfig)'
        MobileApps = 'App'
    }

    $Policies = [System.Collections.Generic.List[object]]::new()
    $IntentIds = [System.Collections.Generic.List[object]]::new()
    $Families = @($Definitions | ForEach-Object { @{ Id = $_.Id; Type = ($Labels[$_.Id] ?? $_.PolicyTypeName ?? $_.Id) } })
    if ($IncludeApps) { $Families += @{ Id = 'MobileApps'; Type = 'App' } }

    foreach ($F in $Families) {
        if (-not (& $Ok $F.Id $F.Type)) { continue }
        foreach ($P in @($ById[$F.Id].body.value)) {
            if ($null -eq $P -or -not $P.id) { continue }
            $Type = $F.Type
            if ($F.Id -eq 'ConfigurationPolicies' -and $P.templateReference.templateFamily -match '^endpointSecurity') { $Type = 'Endpoint Security' }
            $Entry = [pscustomobject]@{
                Id          = [string]$P.id
                Name        = [string]($P.displayName ?? $P.name)
                Type        = $Type
                Family      = $F.Id
                ODataType   = [string]$P.'@odata.type'
                Platforms   = @(Get-CIPPIntunePolicyPlatform -Policy $P -Family $F.Id)
                Assignments = @($P.assignments)
            }
            $Policies.Add($Entry)
            if ($F.Id -eq 'Intents') { $IntentIds.Add($Entry) }
        }
    }

    if ($IntentIds.Count -gt 0) {
        $IntentRequests = @($IntentIds | ForEach-Object { [pscustomobject]@{ id = "intent-$($_.Id)"; method = 'GET'; url = "/deviceManagement/intents/$($_.Id)/assignments" } })
        $IntentResults = @(New-GraphBulkRequest -Requests $IntentRequests -tenantid $TenantFilter)
        foreach ($Entry in $IntentIds) {
            $R = $IntentResults | Where-Object { $_.id -eq "intent-$($Entry.Id)" } | Select-Object -First 1
            if (-not $R -or ($null -ne $R.status -and ($R.status -lt 200 -or $R.status -ge 300))) {
                $Errors.Add("Endpoint Security intent '$($Entry.Name)': assignments could not be read")
                # Unknown, not empty: keep it out of the "no assignments" rule.
                $Entry | Add-Member -NotePropertyName AssignmentsUnknown -NotePropertyValue $true -Force
                continue
            }
            $Entry.Assignments = @($R.body.value)
        }
    }

    $Filters = @{}
    if (& $Ok 'AssignmentFilters' 'Assignment filters') {
        foreach ($F in @($ById['AssignmentFilters'].body.value)) {
            if ($F.id) { $Filters[[string]$F.id] = @{ displayName = [string]$F.displayName; rule = [string]$F.rule; platform = [string]$F.platform } }
        }
    }

    [pscustomobject]@{
        Policies = @($Policies)
        Filters  = $Filters
        Errors   = @($Errors)
    }
}
