function Compare-CIPPOIBVersion {
    <#
    .SYNOPSIS
        Compares deployed (or stored) OIB Windows policies with the latest OIB release.
    .DESCRIPTION
        Each item whose name starts "Win - OIB -" is matched to a release policy, first by the OIBID in its
        description (the current OIBID, or one of the policy's previous-version OIBIDs), then by name: an exact
        match with a deprecated policy, then the version-less BaseKey of an active policy, then the BaseKey of a
        deprecated one. Findings, one per item plus one per unmatched active release policy:

          Current    item version equals the release's version of that policy        Info
          Newer      item version is above the release's (pre-release import)        Info
          Outdated   item version is below the release's, or carries an old OIBID    Warning
          Retired    deprecated in the release, or not in the release at all         Warning
          Unknown    "Win - OIB -" name with no version and no OIBID to match on     Info
          Missing    in the release, nothing matches it here                         Info

        Missing is informational: deploying a subset of OIB is normal. Keys are stable (no versions or dates)
        apart from Outdated/Retired, which embed the version so a fix resolves the old finding.
        Pure: no Graph or table calls. Aspendora fork addition (Vikunja CIPP-20).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # @{ Id; Name; Description; Type } per policy or template.
        [object[]]$Items = @(),
        # Output of ConvertFrom-CIPPOIBRelease (Tag, Version, Policies).
        [Parameter(Mandatory)]$Release,
        [switch]$ExcludeMissing
    )

    $Tag = $Release.Tag
    $Active = @($Release.Policies | Where-Object Status -EQ 'Active')
    $Deprecated = @($Release.Policies | Where-Object Status -EQ 'Deprecated')
    $ById = @{}; $ByPrevId = @{}; $ByKey = @{}; $DepById = @{}; $DepByName = @{}; $DepByKey = @{}
    foreach ($P in $Active) {
        if ($P.OibId) { $ById[$P.OibId] = $P }
        foreach ($Prev in @($P.PreviousIds)) { if ($Prev) { $ByPrevId[$Prev] = $P } }
        if ($P.BaseKey -and -not $ByKey.ContainsKey($P.BaseKey)) { $ByKey[$P.BaseKey] = $P }
    }
    foreach ($P in $Deprecated) {
        if ($P.OibId) { $DepById[$P.OibId] = $P }
        $DepByName[$P.Name.ToLowerInvariant()] = $P
        if ($P.BaseKey -and -not $DepByKey.ContainsKey($P.BaseKey)) { $DepByKey[$P.BaseKey] = $P }
    }
    $ToVersion = { param($V) $Out = $null; if ($V -and [version]::TryParse([string]$V, [ref]$Out)) { $Out } else { $null } }

    $Findings = [System.Collections.Generic.List[object]]::new()
    $Matched = @{}
    $Add = {
        param($State, $Item, $Parsed, $Policy, $Message)
        $Severity = if ($State -in @('Outdated', 'Retired')) { 'Warning' } else { 'Info' }
        $Ident = if ($Item.Id) { $Item.Id } else { $Parsed.BaseKey ?? $Policy.BaseKey }
        $KeyVer = if ($State -in @('Outdated', 'Retired')) { "|$($Parsed.Version)" } else { '' }
        $Findings.Add([pscustomobject]@{
                Key            = "$State|$Ident$KeyVer"
                State          = $State
                Severity       = $Severity
                Name           = if ($Item) { [string]$Item.Name } else { [string]$Policy.Name }
                Type           = if ($Item) { [string]$Item.Type } else { [string]$Policy.PolicyType }
                CurrentVersion = $Parsed.Version
                LatestVersion  = $Policy.Version
                LatestName     = if ($Policy -and $Policy.Status -eq 'Active') { $Policy.Name } else { $null }
                ReleaseTag     = $Tag
                Message        = $Message
                Id             = if ($Item) { [string]$Item.Id } else { $null }
            })
    }

    foreach ($Item in @($Items)) {
        if ($null -eq $Item) { continue }
        $Parsed = ConvertFrom-CIPPOIBPolicyName -Name $Item.Name -Description $Item.Description
        if (-not $Parsed.IsOib) { continue }

        $Policy = $null; $Dep = $null; $OldId = $false
        if ($Parsed.OibId -and $ById.ContainsKey($Parsed.OibId)) { $Policy = $ById[$Parsed.OibId] }
        elseif ($Parsed.OibId -and $ByPrevId.ContainsKey($Parsed.OibId)) { $Policy = $ByPrevId[$Parsed.OibId]; $OldId = $true }
        elseif ($Parsed.OibId -and $DepById.ContainsKey($Parsed.OibId)) { $Dep = $DepById[$Parsed.OibId] }
        elseif ($DepByName.ContainsKey(([string]$Item.Name).Trim().ToLowerInvariant())) { $Dep = $DepByName[([string]$Item.Name).Trim().ToLowerInvariant()] }
        elseif ($Parsed.BaseKey -and $ByKey.ContainsKey($Parsed.BaseKey)) { $Policy = $ByKey[$Parsed.BaseKey] }
        elseif ($Parsed.BaseKey -and $DepByKey.ContainsKey($Parsed.BaseKey)) { $Dep = $DepByKey[$Parsed.BaseKey] }

        if ($Policy) {
            $Matched[$Policy.Name] = $true
            $Have = & $ToVersion $Parsed.Version
            $Want = & $ToVersion $Policy.Version
            if ($OldId -and -not ($Have -and $Want -and $Have -gt $Want)) {
                $From = $Parsed.Version ?? 'an earlier version'
                & $Add 'Outdated' $Item $Parsed $Policy "'$($Item.Name)' is an earlier OIB build of '$($Policy.Name)' (its OIBID belongs to a previous version). Update $From -> v$($Policy.Version) from OIB $Tag."
            } elseif (-not $Have) {
                & $Add 'Unknown' $Item $Parsed $Policy "'$($Item.Name)' looks like OIB policy '$($Policy.Name)' but its name carries no version to compare."
            } elseif (-not $Want -or $Have -eq $Want) {
                & $Add 'Current' $Item $Parsed $Policy "'$($Item.Name)' is current (v$($Parsed.Version) in OIB $Tag)."
            } elseif ($Have -lt $Want) {
                & $Add 'Outdated' $Item $Parsed $Policy "'$($Item.Name)' is v$($Parsed.Version); OIB $Tag ships v$($Policy.Version) ('$($Policy.Name)'). Update v$($Parsed.Version) -> v$($Policy.Version)."
            } else {
                & $Add 'Newer' $Item $Parsed $Policy "'$($Item.Name)' is v$($Parsed.Version), newer than the v$($Policy.Version) in OIB $Tag (taken from a branch or pre-release)."
            }
        } elseif ($Dep) {
            $Repl = @($Dep.SupersededBy | Where-Object { $_ })
            $Then = if ($Repl.Count -gt 0) { " Replaced by: $($Repl -join '; ')." } else { ' It has no replacement; remove it once nothing depends on it.' }
            & $Add 'Retired' $Item $Parsed $Dep "'$($Item.Name)' is deprecated in OIB $Tag.$Then"
        } elseif (-not $Parsed.Version -and -not $Parsed.OibId) {
            & $Add 'Unknown' $Item $Parsed $null "'$($Item.Name)' has an OIB-style name but no version or OIBID, and matches no policy in OIB $Tag."
        } else {
            & $Add 'Retired' $Item $Parsed $null "'$($Item.Name)' is not in OIB $Tag. It was dropped or renamed upstream; check the OIB changelog and replace or remove it."
        }
    }

    if (-not $ExcludeMissing) {
        foreach ($P in $Active) {
            if ($Matched.ContainsKey($P.Name)) { continue }
            & $Add 'Missing' $null ([pscustomobject]@{ Version = $null; BaseKey = $P.BaseKey }) $P "'$($P.Name)' (OIB $Tag) is not present here."
        }
    }
    @($Findings)
}
