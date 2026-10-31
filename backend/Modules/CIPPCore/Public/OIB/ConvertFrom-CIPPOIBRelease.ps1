function ConvertFrom-CIPPOIBRelease {
    <#
    .SYNOPSIS
        Builds the OIB Windows policy list for one release from its git tree paths and PolicyManifest.json.
    .DESCRIPTION
        The release's policy files (WINDOWS/IntuneManagement/<PolicyType>/<name>.json) are the active set.
        WINDOWS/PolicyManifest.json (present from windows-v4.0) adds each policy's OIBID, the OIBIDs of its
        previous versions, and the deprecated policies with what superseded them; without a manifest the
        file names alone are used and nothing is known to be deprecated.
        Returns @{ Tag; Version; Policies } where each policy is
        @{ Name; BaseKey; Version; PolicyType; Status ('Active' | 'Deprecated'); OibId; PreviousIds; SupersededBy }.
        Pure: no GitHub or table calls. Aspendora fork addition (Vikunja CIPP-20).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Tag,
        # Blob paths from the git tree at the tag.
        [string[]]$Paths = @(),
        # Parsed WINDOWS/PolicyManifest.json, or $null.
        $Manifest
    )

    $ManifestByName = @{}
    $NameById = @{}
    foreach ($M in @($Manifest.policies)) {
        if (-not $M.name) { continue }
        $ManifestByName[$M.name.ToLowerInvariant()] = $M
        if ($M.oibId) { $NameById[([string]$M.oibId).ToUpperInvariant()] = [string]$M.name }
    }

    $New = {
        param($Name, $PolicyType, $Status, $M)
        $P = ConvertFrom-CIPPOIBPolicyName -Name $Name
        [pscustomobject]@{
            Name         = $Name
            BaseKey      = $P.BaseKey
            Version      = $P.Version
            PolicyType   = $PolicyType
            Status       = $Status
            OibId        = if ($M.oibId) { ([string]$M.oibId).ToUpperInvariant() } else { $null }
            PreviousIds  = @($M.previousVersions | Where-Object { $_.oibId } | ForEach-Object { ([string]$_.oibId).ToUpperInvariant() })
            SupersededBy = @($M.supersededBy | Where-Object { $_ } | ForEach-Object { $NameById[([string]$_).ToUpperInvariant()] ?? [string]$_ })
        }
    }

    $Policies = [System.Collections.Generic.List[object]]::new()
    $Seen = @{}
    foreach ($Path in $Paths) {
        if (-not ($Path -match '^WINDOWS/IntuneManagement/(?<type>[^/]+)/(?<file>[^/]+)\.json$')) { continue }
        $Name = $Matches.file
        $Type = $Matches.type
        if (-not (ConvertFrom-CIPPOIBPolicyName -Name $Name).IsOib) { continue }
        if ($Seen.ContainsKey($Name.ToLowerInvariant())) { continue }
        $Seen[$Name.ToLowerInvariant()] = $true
        $Policies.Add((& $New $Name $Type 'Active' $ManifestByName[$Name.ToLowerInvariant()]))
    }
    # No policy files (tree unreadable or layout changed): fall back to the manifest's active list.
    if ($Policies.Count -eq 0) {
        foreach ($M in @($Manifest.policies | Where-Object { $_.status -eq 'active' })) {
            $Seen[$M.name.ToLowerInvariant()] = $true
            $Policies.Add((& $New $M.name $M.policyType 'Active' $M))
        }
    }
    foreach ($M in @($Manifest.policies | Where-Object { $_.status -and $_.status -ne 'active' })) {
        if ($Seen.ContainsKey($M.name.ToLowerInvariant())) { continue }
        $Policies.Add((& $New $M.name $M.policyType 'Deprecated' $M))
    }

    [pscustomobject]@{
        Tag      = $Tag
        Version  = ($Tag -replace '^windows-v', '')
        Policies = @($Policies)
    }
}
