function Get-CIPPOIBDrift {
    <#
    .SYNOPSIS
        OIB version drift for a tenant's Intune policies, or for the CIPP Intune template library.
    .DESCRIPTION
        Collects every "Win - OIB -" item and compares it with the latest OIB Windows release
        (Get-CIPPOIBLatestRelease, cached a day) using Compare-CIPPOIBVersion.
        Tenant mode reads Settings Catalog / Endpoint Security (configurationPolicies), compliance policies,
        device configurations (templates, WUfB rings), driver update profiles and legacy intents; each read
        that fails is listed in Errors rather than taken as "no policies".
        -TemplateLibrary reads the IntuneTemplate rows of the CIPP templates table instead, so stored templates
        that have fallen behind the release show up before anyone deploys them.
        Returns @{ Scope; ReleaseTag; ReleaseUrl; ReleaseFetchedAt; ReleaseStale; OibItemCount; Summary;
        Findings; Errors }. Read only. Aspendora fork addition (Vikunja CIPP-20).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding(DefaultParameterSetName = 'Tenant')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Tenant')][string]$TenantFilter,
        [Parameter(Mandatory, ParameterSetName = 'Templates')][switch]$TemplateLibrary,
        [switch]$RefreshRelease,
        [switch]$ExcludeMissing
    )

    $Release = Get-CIPPOIBLatestRelease -Force:$RefreshRelease
    $Errors = [System.Collections.Generic.List[string]]::new()
    $Items = [System.Collections.Generic.List[object]]::new()

    if ($TemplateLibrary) {
        $Scope = 'TemplateLibrary'
        $Table = Get-CippTable -tablename 'templates'
        foreach ($Row in @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'IntuneTemplate'")) {
            try {
                $Data = $Row.JSON | ConvertFrom-Json -Depth 100 -ErrorAction Stop
                $Raw = try { $Data.RAWJson | ConvertFrom-Json -Depth 100 -ErrorAction Stop } catch { $null }
                $Name = $Data.Displayname ?? $Raw.displayName ?? $Raw.name
                if ([string]$Name -notmatch '^\s*Win\s*-\s*OIB\s*-') { continue }
                $Items.Add([pscustomobject]@{
                        Id          = [string]$Row.RowKey
                        Name        = [string]$Name
                        Description = "$($Data.Description) $($Raw.description)"
                        Type        = "Template ($($Data.Type))$(if ($Row.Source) { " from $($Row.Source)" })"
                    })
            } catch {
                $Errors.Add("Template $($Row.RowKey): unreadable JSON")
            }
        }
    } else {
        $Scope = $TenantFilter
        $Collections = @(
            @{ Type = 'Settings Catalog'; Uri = 'configurationPolicies?$select=id,name,description&$top=1000'; NameProp = 'name' }
            @{ Type = 'Compliance Policy'; Uri = 'deviceCompliancePolicies?$select=id,displayName,description&$top=1000'; NameProp = 'displayName' }
            @{ Type = 'Device Configuration'; Uri = 'deviceConfigurations?$select=id,displayName,description&$top=1000'; NameProp = 'displayName' }
            @{ Type = 'Driver Update'; Uri = 'windowsDriverUpdateProfiles?$top=200'; NameProp = 'displayName' }
            @{ Type = 'Endpoint Security (intent)'; Uri = 'intents?$top=1000'; NameProp = 'displayName' }
        )
        foreach ($C in $Collections) {
            try {
                $Policies = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/deviceManagement/$($C.Uri)" -tenantid $TenantFilter -ErrorAction Stop)
                foreach ($P in $Policies) {
                    if ($null -eq $P) { continue }
                    $Name = [string]$P.($C.NameProp)
                    if ($Name -notmatch '^\s*Win\s*-\s*OIB\s*-') { continue }
                    $Items.Add([pscustomobject]@{ Id = [string]$P.id; Name = $Name; Description = [string]$P.description; Type = $C.Type })
                }
            } catch {
                $Errors.Add("$($C.Type): $((Get-CippException -Exception $_).NormalizedError)")
            }
        }
    }

    $Findings = @(Compare-CIPPOIBVersion -Items @($Items) -Release $Release -ExcludeMissing:$ExcludeMissing)
    $Summary = [ordered]@{}
    foreach ($State in 'Current', 'Outdated', 'Retired', 'Newer', 'Unknown', 'Missing') {
        $Summary[$State] = @($Findings | Where-Object State -EQ $State).Count
    }

    [pscustomobject]@{
        Scope            = $Scope
        ReleaseTag       = $Release.Tag
        ReleaseUrl       = $Release.Url
        ReleaseFetchedAt = $Release.FetchedAt
        ReleaseStale     = [bool]$Release.Stale
        ReleasePolicies  = @($Release.Policies | Where-Object Status -EQ 'Active').Count
        OibItemCount     = $Items.Count
        Summary          = [pscustomobject]$Summary
        Findings         = @($Findings)
        Errors           = @($Errors)
    }
}
