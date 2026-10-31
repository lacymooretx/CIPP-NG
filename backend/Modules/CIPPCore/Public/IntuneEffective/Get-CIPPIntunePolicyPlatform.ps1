function Get-CIPPIntunePolicyPlatform {
    <#
    .SYNOPSIS
        Normalises an Intune policy's (or a device's) platform to windows / macOS / iOS / android / linux.
    .DESCRIPTION
        Pure function. With -OperatingSystem, normalises a managedDevice.operatingSystem value. Otherwise returns the
        platform(s) a policy object targets, from Settings Catalog "platforms", or the @odata.type of device
        configurations, compliance policies and apps, or the family (Administrative Templates, endpoint security
        intents, Windows update profiles and BIOS configurations are Windows-only). Returns an empty array when the
        platform cannot be determined; callers must then NOT skip the policy on platform grounds.
        Aspendora fork addition (Vikunja CIPP-19).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        $Policy,
        [string]$Family,
        [string]$OperatingSystem
    )

    $FromText = {
        param([string]$Text)
        $T = $Text.ToLowerInvariant()
        if ($T -match '^(ios|ipados|managedios)') { return 'iOS' }
        if ($T -match '^(macos|mac)') { return 'macOS' }
        if ($T -match '^(android|aosp|managedandroid)') { return 'android' }
        if ($T -match '^linux') { return 'linux' }
        if ($T -match '^(windows|win32|wingetapp|win|officesuiteapp|microsoftstoreforbusiness|editionupgrade|sharedpc)') { return 'windows' }
        return $null
    }

    if ($PSBoundParameters.ContainsKey('OperatingSystem')) {
        if (-not $OperatingSystem) { return $null }
        return (& $FromText $OperatingSystem)
    }

    if ($Family -in @('GroupPolicyConfigurations', 'Intents', 'WindowsDriverUpdateProfiles', 'WindowsFeatureUpdateProfiles', 'windowsQualityUpdatePolicies', 'windowsQualityUpdateProfiles', 'hardwareConfigurations')) {
        return @('windows')
    }

    if ($Policy.platforms) {
        # Settings Catalog: "windows10", "macOS", "iOS", "android", "androidEnterprise", "aosp", "linux"; may be a flags list.
        return @(([string]$Policy.platforms -split '[,\s]+') | Where-Object { $_ -and $_ -ne 'none' } | ForEach-Object { & $FromText $_ } | Where-Object { $_ } | Sort-Object -Unique)
    }

    $OData = [string]$Policy.'@odata.type'
    if ($OData) {
        $TypeName = $OData -replace '^#?microsoft\.graph\.', ''
        if ($TypeName -match '^(webApp|.*webLink)$') { return @() } # web links are cross-platform
        $P = & $FromText $TypeName
        if ($P) { return @($P) }
    }
    return @()
}
