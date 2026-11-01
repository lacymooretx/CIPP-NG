function Test-CIPPIntuneCloudOnlyLint {
    <#
    .SYNOPSIS
        Flags Intune settings known to misbehave, or to do nothing, on Entra joined (cloud-only) devices.
    .DESCRIPTION
        Pure function: no Graph calls. Each policy's Body is matched against the rules in
        Config/IntuneCloudOnlyLintRules.json (or -Rules). Three shapes are understood:
          - Settings Catalog: Body.settings[] (settingInstance trees). Walked with
            ConvertFrom-CIPPIntuneSettingInstance, so nested children (a LAPS BackupDirectory choice and the
            settings under it, a Windows Hello group collection) are checked too.
          - Custom (OMA-URI) device configuration: Body.omaSettings[] (omaUri + value). An encrypted value Graph
            would not return (isEncrypted, secretReferenceValueId, or the PGEvPg== placeholder) still matches on
            the URI, with ValueVerified = $false, rather than being silently skipped.
          - Administrative Templates: Body.added[] (a CIPP 'Admin' template's updateDefinitionValues payload)
            or Body.definitionValues[] (a live policy read with $expand=definition). Matched on the definition id
            (built-in ADMX ids are the same in every tenant), display name or category path.
        Anything else (compliance policies, app protection, a body that is not JSON) yields no findings and never
        throws: the lint is advisory and must not take a report or a template save down with it.

        One finding per policy per rule, listing every matching setting. Relevance is worked out from -Context:
        a CloudOnlyDevices rule matters only when the tenant has Entra joined (not hybrid) Windows devices, and a
        NoOnPremisesDirectory rule only when the tenant does not sync from on-premises Active Directory. Without a
        context (template mode) Relevance is 'Unknown'.
        Aspendora fork addition (Vikunja CIPP-28).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        # @{ Id; Name; Type; Assigned (bool or $null); Body (object, or a JSON string) }
        [object[]]$Policies = @(),
        # The 'rules' array of IntuneCloudOnlyLintRules.json. Loaded from the Config folder when omitted.
        [object[]]$Rules,
        # @{ CloudOnlyDevices = [int] or $null; HybridDevices = [int] or $null; DirectorySynced = [bool] or $null }
        $Context
    )

    if (-not $PSBoundParameters.ContainsKey('Rules')) {
        $RulesPath = Join-Path $env:CIPPRootPath 'Config/IntuneCloudOnlyLintRules.json'
        $Rules = @((Get-Content -Path $RulesPath -Raw -ErrorAction Stop | ConvertFrom-Json).rules)
    }
    $Rules = @($Rules | Where-Object { $_ -and $_.id })

    # --- matching helpers -------------------------------------------------------------------------------
    $List = { param($Value) @($Value | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [string]$_ }) }

    $DefinitionMatches = {
        param($Rule, [string]$DefinitionId)
        if (-not $DefinitionId) { return $false }
        foreach ($Id in (& $List $Rule.match.settingDefinitionIds)) { if ($DefinitionId -eq $Id) { return $true } }
        foreach ($Prefix in (& $List $Rule.match.settingDefinitionIdPrefixes)) {
            if ($DefinitionId.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    }

    # A choice value repeats the definition id with the option appended (<def>_1, <def>_true); a simple value is
    # the bare value (30, true). An empty 'values' list means any value is a finding.
    $ValueMatches = {
        param($Rule, [string]$DefinitionId, $RawValue)
        $Accepted = & $List $Rule.match.values
        if ($Accepted.Count -eq 0) { return $true }
        foreach ($V in @($RawValue)) {
            if ($null -eq $V) { continue }
            $S = [string]$V
            foreach ($A in $Accepted) {
                if ($S -eq $A -or $S -eq "${DefinitionId}_$A") { return $true }
            }
        }
        return $false
    }

    $AdmxId = {
        param($Entry)
        if ($Entry.definition.id) { return [string]$Entry.definition.id }
        $Bind = [string]$Entry.'definition@odata.bind'
        # [regex]::Match, not -match: -match would overwrite the caller's $Matches.
        $M = [regex]::Match($Bind, "groupPolicyDefinitions\('([^']+)'\)")
        if ($M.Success) { return $M.Groups[1].Value }
        return $null
    }

    $Relevance = {
        param([string]$AppliesWhen)
        if ($null -eq $Context) { return @('Unknown', 'Template or no tenant context: check whether the target devices are Entra joined.') }
        switch ($AppliesWhen) {
            'NoOnPremisesDirectory' {
                if ($null -eq $Context.DirectorySynced) { return @('Unknown', 'Directory sync state could not be read.') }
                if ($Context.DirectorySynced -eq $true) { return @('Check', 'The tenant syncs from on-premises Active Directory, so this may be intentional for devices that reach AD.') }
                return @('Applies', 'The tenant has no on-premises directory sync.')
            }
            default {
                if ($null -eq $Context.CloudOnlyDevices) { return @('Unknown', 'Windows device join types could not be read.') }
                if ([int]$Context.CloudOnlyDevices -gt 0) { return @('Applies', "$([int]$Context.CloudOnlyDevices) Entra joined (cloud-only) Windows device(s) in the tenant.") }
                return @('Not applicable', 'No Entra joined (cloud-only) Windows devices in the tenant; every Windows device is hybrid joined or registered.')
            }
        }
    }

    $SeverityOrder = @{ High = 0; Medium = 1; Low = 2; Info = 3 }

    # --- walk each policy ------------------------------------------------------------------------------
    $Findings = [System.Collections.Generic.List[object]]::new()
    foreach ($Policy in @($Policies)) {
        if ($null -eq $Policy) { continue }
        $Body = $Policy.Body
        if ($Body -is [string]) {
            try { $Body = $Body | ConvertFrom-Json -Depth 100 -ErrorAction Stop } catch { continue }
        }
        if ($null -eq $Body) { continue }

        # RuleId -> @{ Settings = list; Via = string; Verified = bool }
        $Hits = [ordered]@{}
        $AddHit = {
            param($Rule, [string]$Setting, [string]$Via, [bool]$Verified)
            if (-not $Hits.Contains($Rule.id)) { $Hits[$Rule.id] = @{ Rule = $Rule; Settings = [System.Collections.Generic.List[string]]::new(); Via = $Via; Verified = $true } }
            if (-not $Hits[$Rule.id].Settings.Contains($Setting)) { $Hits[$Rule.id].Settings.Add($Setting) }
            if (-not $Verified) { $Hits[$Rule.id].Verified = $false }
        }

        try {
            # Settings Catalog
            foreach ($S in @($Body.settings)) {
                if ($null -eq $S) { continue }
                foreach ($Row in @(ConvertFrom-CIPPIntuneSettingInstance -Instance $S)) {
                    $Def = [string]$Row.DefinitionId
                    foreach ($Rule in $Rules) {
                        if ((& $DefinitionMatches $Rule $Def) -and (& $ValueMatches $Rule $Def $Row.RawValue)) {
                            & $AddHit $Rule "$($Row.Setting) = $($Row.Value)" 'Settings Catalog' $true
                        }
                    }
                }
            }

            # Custom OMA-URI
            foreach ($Oma in @($Body.omaSettings)) {
                if ($null -eq $Oma -or -not $Oma.omaUri) { continue }
                $Uri = [string]$Oma.omaUri
                $Unreadable = [bool]($Oma.isEncrypted -eq $true -or $Oma.secretReferenceValueId -or "$($Oma.value)" -eq 'PGEvPg==')
                foreach ($Rule in $Rules) {
                    $UriHit = $false
                    foreach ($Pattern in (& $List $Rule.match.omaUris)) { if ($Uri -like $Pattern) { $UriHit = $true; break } }
                    if (-not $UriHit) { continue }
                    $ValuePatterns = & $List $Rule.match.omaValues
                    if ($ValuePatterns.Count -eq 0) { & $AddHit $Rule "$Uri = $($Oma.value)" 'OMA-URI' $true; continue }
                    if ($Unreadable) { & $AddHit $Rule "$Uri (value encrypted, not checked)" 'OMA-URI' $false; continue }
                    $Value = [string]$Oma.value
                    foreach ($Pattern in $ValuePatterns) {
                        if ($Value -like $Pattern) { & $AddHit $Rule "$Uri = $Value" 'OMA-URI' $true; break }
                    }
                }
            }

            # Administrative Templates: template payload (added) or live definition values.
            foreach ($Entry in @(@($Body.added) + @($Body.definitionValues))) {
                if ($null -eq $Entry) { continue }
                $Id = & $AdmxId $Entry
                $Name = [string]$Entry.definition.displayName
                $Category = [string]$Entry.definition.categoryPath
                $Enabled = $Entry.enabled -eq $true
                foreach ($Rule in $Rules) {
                    $Hit = ($Id -and (& $List $Rule.match.admxDefinitionIds) -contains $Id) -or
                    ($Name -and (& $List $Rule.match.admxDisplayNames) -contains $Name)
                    if (-not $Hit -and $Category) {
                        foreach ($Prefix in (& $List $Rule.match.admxCategoryPathPrefixes)) {
                            if ($Category.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) { $Hit = $true; break }
                        }
                    }
                    if (-not $Hit) { continue }
                    if ($Rule.match.admxEnabledOnly -eq $true -and -not $Enabled) { continue }
                    $Label = if ($Name) { $Name } else { "Definition $Id" }
                    & $AddHit $Rule "$Label = $(if ($Enabled) { 'Enabled' } else { 'Disabled' })" 'Administrative Template' $true
                }
            }
        } catch {
            # Unknown or malformed shape: report what was found so far, never throw.
            Write-Verbose "Cloud-only lint skipped part of '$($Policy.Name)': $($_.Exception.Message)"
        }

        foreach ($Key in $Hits.Keys) {
            $H = $Hits[$Key]
            $Rule = $H.Rule
            $Rel = & $Relevance ([string]$Rule.appliesWhen)
            $Sources = @(& $List $Rule.sources)
            $Findings.Add([pscustomobject]@{
                    RuleId          = [string]$Rule.id
                    Title           = [string]$Rule.title
                    Severity        = [string]$Rule.severity
                    PolicyId        = [string]$Policy.Id
                    PolicyName      = [string]$Policy.Name
                    PolicyType      = [string]$Policy.Type
                    Assigned        = $Policy.Assigned
                    MatchedVia      = $H.Via
                    Settings        = ($H.Settings -join ' | ')
                    ValueVerified   = $H.Verified
                    Relevance       = $Rel[0]
                    RelevanceReason = $Rel[1]
                    AppliesWhen     = [string]$Rule.appliesWhen
                    Symptom         = [string]$Rule.symptom
                    Why             = [string]$Rule.why
                    Alternative     = [string]$Rule.alternative
                    Source          = ($Sources | Select-Object -First 1)
                    Sources         = @($Sources)
                })
        }
    }

    # Emit items (no unary-comma return): callers collect with @().
    $Findings | Sort-Object @{ Expression = { $SeverityOrder[[string]$_.Severity] ?? 9 } }, PolicyName, RuleId
}
