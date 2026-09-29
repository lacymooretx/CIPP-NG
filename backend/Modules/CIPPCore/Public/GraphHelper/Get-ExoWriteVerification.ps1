function Get-ExoWriteVerification {
    <#
    .FUNCTIONALITY
        Internal
    .DESCRIPTION
        Reads an object back after a Set-* cmdlet and compares each requested scalar property with
        what Get-* now reports. Never throws: a read-back that can't be done is 'Skipped'.
    #>
    param($Cmdlet, $ParamHash, [hashtable]$ReadParams)

    # Parameters that steer the cmdlet rather than set a property.
    $NonProperty = @('Identity', 'Confirm', 'Force', 'WhatIf', 'DomainController', 'ErrorAction', 'WarningAction',
        'IgnoreDefaultScope', 'Verbose', 'Debug')
    $LagNote = 'Exchange accepted the write without error, but the read-back does not show it. EXO reads can lag a write by several minutes, and some properties are never reflected by Get-*. To confirm, search the unified audit log: Search-UnifiedAuditLog -RecordType ExchangeAdmin -Operations ' + $Cmdlet + ' (ObjectIds as an array; it matches the display name).'

    $Wanted = [ordered]@{}
    $NotComparable = [System.Collections.Generic.List[string]]::new()
    if ($ParamHash) {
        foreach ($Key in $ParamHash.Keys) {
            if ($Key -in $NonProperty) { continue }
            $Value = $ParamHash[$Key]
            # @{Add=...;Remove=...} multi-value edits and nested objects can't be compared to the result.
            if ($Value -is [hashtable] -or $Value -is [System.Management.Automation.PSCustomObject]) { $NotComparable.Add($Key); continue }
            $Wanted[$Key] = $Value
        }
    }
    if ($Wanted.Count -eq 0) {
        return [pscustomobject]@{ Status = 'Skipped'; Properties = @(); Note = 'No directly comparable properties were set.' }
    }

    $GetCmdlet = $Cmdlet -replace '^Set-', 'Get-'
    $GetParams = @{ tenantid = $ReadParams.tenantid; cmdlet = $GetCmdlet }
    if ($ParamHash -and $ParamHash.ContainsKey('Identity')) { $GetParams.cmdParams = @{ Identity = $ParamHash['Identity'] } }
    if ($ReadParams.Compliance) { $GetParams.Compliance = $true }
    if ($ReadParams.Anchor) { $GetParams.Anchor = $ReadParams.Anchor }

    try {
        $Current = @(New-ExoRequest @GetParams)
    } catch {
        return [pscustomobject]@{ Status = 'Skipped'; Properties = @(); Note = "Read-back with $GetCmdlet failed: $($_.Exception.Message)" }
    }
    if ($Current.Count -ne 1) {
        return [pscustomobject]@{ Status = 'Skipped'; Properties = @(); Note = "Read-back with $GetCmdlet returned $($Current.Count) objects; can't tell which one was changed." }
    }
    $Object = $Current[0]

    $Normalize = {
        param($V)
        if ($null -eq $V) { return '' }
        if ($V -is [System.Collections.IEnumerable] -and $V -isnot [string]) {
            return ((@($V) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object) -join '|')
        }
        return "$V".Trim().ToLowerInvariant()
    }

    $Properties = foreach ($Name in $Wanted.Keys) {
        $Present = $Object.PSObject.Properties.Name -contains $Name
        $Observed = if ($Present) { $Object.$Name } else { $null }
        [pscustomobject]@{
            Name      = $Name
            Requested = $Wanted[$Name]
            Observed  = $Observed
            Match     = $Present -and ((& $Normalize $Wanted[$Name]) -eq (& $Normalize $Observed))
        }
    }
    $Properties = @($Properties)
    $AllMatch = -not ($Properties | Where-Object { -not $_.Match })
    $Note = if ($AllMatch) { "$GetCmdlet shows every requested value." } else { $LagNote }
    if ($NotComparable.Count -gt 0) { $Note += " Not compared (multi-value or nested): $($NotComparable -join ', ')." }

    [pscustomobject]@{
        Status     = if ($AllMatch) { 'Confirmed' } else { 'Mismatch' }
        Properties = $Properties
        Note       = $Note
    }
}
