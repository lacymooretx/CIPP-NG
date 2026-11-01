function Get-CIPPDefenderPolicyInventory {
    <#
    .SYNOPSIS
        Every Windows Settings Catalog / endpoint security policy in a tenant, with assignments and the Defender
        hardening settings it sets (ASR rules, Network Protection, Device Control).
    .DESCRIPTION
        Read-only. One GET of /deviceManagement/configurationPolicies with $expand=assignments,settings (the same
        expansion the CIPP report cache uses), parsed with ConvertFrom-CIPPDefenderPolicySettings. Group names in
        assignment labels come from one bulk read of the include groups.
        Legacy endpoint security intents (deviceManagement/intents) are listed in Notes but not parsed: their
        settings live in a different schema. Device configuration profiles (windows10EndpointProtectionConfiguration)
        are not inspected either. Returns @{ Policies; Errors; Notes }. Aspendora fork addition (Vikunja CIPP-26).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TenantFilter)

    $Errors = [System.Collections.Generic.List[string]]::new()
    $Notes = [System.Collections.Generic.List[string]]::new()
    $Raw = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$select=id,name,platforms,technologies,templateReference,settingCount&`$expand=assignments,settings&`$top=1000" -tenantid $TenantFilter -ErrorAction Stop)
    $Raw = @($Raw | Where-Object { $_ -and ([string]$_.platforms) -match 'windows' })

    $GroupIds = @($Raw | ForEach-Object { @($_.assignments) } | ForEach-Object { [string]$_.target.groupId } | Where-Object { $_ } | Sort-Object -Unique)
    $GroupNames = @{}
    if ($GroupIds.Count -gt 0) {
        try {
            $Requests = @($GroupIds | ForEach-Object { [pscustomobject]@{ id = $_; method = 'GET'; url = "/groups/$_`?`$select=id,displayName" } })
            foreach ($R in @(New-GraphBulkRequest -Requests $Requests -tenantid $TenantFilter)) {
                if ($R.body.displayName) { $GroupNames[[string]$R.id] = [string]$R.body.displayName }
            }
        } catch { $Notes.Add("group names could not be read: $((Get-CippException -Exception $_).NormalizedError)") }
    }

    $Policies = foreach ($P in $Raw) {
        if ($null -ne $P.settingCount -and @($P.settings).Count -lt [int]$P.settingCount) {
            # Not seen live (2026-10-31: 120 of 120 returned) but would silently hide a setting if Graph ever paged it.
            $Errors.Add("policy '$($P.name)': only $(@($P.settings).Count) of $($P.settingCount) settings were returned")
        }
        $State = Get-CIPPIntunePolicyAssignmentState -Assignments @($P.assignments) -GroupNames $GroupNames
        [pscustomobject]@{
            Id              = [string]$P.id
            Name            = [string]$P.name
            TemplateFamily  = [string]$P.templateReference.templateFamily
            TemplateName    = [string]$P.templateReference.templateDisplayName
            Assigned        = $State.Assigned
            AssignmentLabel = $State.Label
            Parsed          = ConvertFrom-CIPPDefenderPolicySettings -Settings @($P.settings)
        }
    }

    try {
        $Intents = @(New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/deviceManagement/intents?$select=id,displayName,templateId' -tenantid $TenantFilter)
        if ($Intents.Count -gt 0) {
            $Notes.Add("$($Intents.Count) legacy endpoint security intent(s) were not inspected: $((@($Intents.displayName) | Select-Object -First 5) -join ', ')")
        }
    } catch { $Errors.Add("legacy intents: $((Get-CippException -Exception $_).NormalizedError)") }

    [pscustomobject]@{ Policies = @($Policies); Errors = @($Errors); Notes = @($Notes) }
}
