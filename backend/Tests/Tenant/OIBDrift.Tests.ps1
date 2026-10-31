# Aspendora fork (Vikunja CIPP-20): OpenIntuneBaseline (OIB) version drift.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $OibDir = Join-Path $RepoRoot 'Modules/CIPPCore/Public/OIB'
    foreach ($File in 'ConvertFrom-CIPPOIBPolicyName', 'ConvertFrom-CIPPOIBRelease', 'Compare-CIPPOIBVersion', 'Get-CIPPOIBLatestRelease', 'Get-CIPPOIBDrift') {
        . (Join-Path $OibDir "$File.ps1")
    }

    # Stubs for the CIPP helpers the collectors call; each test mocks what it needs.
    function Get-CIPPTable { [CmdletBinding()] param($TableName) }
    function Get-CIPPAzDataTableEntity { [CmdletBinding()] param($Filter) }
    function Add-CIPPAzDataTableEntity { [CmdletBinding()] param($Entity, [switch]$Force) }
    function Invoke-GitHubApiRequest { [CmdletBinding()] param($Path, $Method) }
    function Get-GitHubFileTree { [CmdletBinding()] param($FullName, $Branch) }
    function Get-GitHubFileContents { [CmdletBinding()] param($FullName, $Path, $Branch) }
    function Write-LogMessage { [CmdletBinding()] param($API, $tenant, $message, $sev) }
    function New-GraphGetRequest { [CmdletBinding()] param($uri, $tenantid) }
    function Get-CippException { [CmdletBinding()] param($Exception) [pscustomobject]@{ NormalizedError = 'denied' } }

    $script:AV4 = '2064828D-FB90-4A27-B4F9-3EE30F5A4DA2'
    $script:AV3 = '80C1B821-B768-43A5-B318-7E2A54290FD8'
    $script:LAPS4 = '9E4838C2-960E-47B9-B21F-2AFF6550F285'
    $script:LAPS3 = '11111111-2222-3333-4444-555555555555'
    $script:TPM4 = '24BFFF77-81DC-4867-A8F8-BA8249CAE404'
    $script:PWD3 = '66666666-7777-8888-9999-AAAAAAAAAAAA'

    $script:Paths = @(
        'WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - SC - Microsoft Edge - D - Security - v4.0.json'
        'WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - ES - Defender Antivirus - D - AV Configuration - v4.0.json'
        'WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - ES - Windows LAPS - D - LAPS Configuration - v4.0.json'
        'WINDOWS/IntuneManagement/CompliancePolicies/Win - OIB - CP - Device Security - U - TPM - v4.0.json'
        'WINDOWS/IntuneManagement/DriverUpdateProfiles/Win - OIB - WUfB Drivers - Ring 1 - Pilot - v3.0.json'
        'WINDOWS/IntuneManagement/SettingsCatalog/Win - OIB - SC - Microsoft Office - D - Updates - v3.0.json'
        'WINDOWS365/IntuneManagement/SettingsCatalog/Win365 - OIB - Device Security - D - Connectivity Settings - v1.0.json'
        'MACOS/IntuneManagement/SettingsCatalog/MacOS - OIB - Firewall - D - Gatekeeper - v1.0.json'
        'WINDOWS/README.md'
    )
    $script:Manifest = [pscustomobject]@{
        oibVersion = '4.0'
        policies   = @(
            [pscustomobject]@{ oibId = $script:AV4; name = 'Win - OIB - ES - Defender Antivirus - D - AV Configuration - v4.0'; status = 'active'; policyType = 'EndpointSecurity'; supersededBy = @(); previousVersions = @([pscustomobject]@{ oibVersion = '3.3'; oibId = $script:AV3 }) }
            [pscustomobject]@{ oibId = $script:LAPS4; name = 'Win - OIB - ES - Windows LAPS - D - LAPS Configuration - v4.0'; status = 'active'; policyType = 'EndpointSecurity'; supersededBy = @(); previousVersions = @() }
            [pscustomobject]@{ oibId = $script:LAPS3; name = 'Win - OIB - ES - Windows LAPS - D - LAPS Configuration - v3.1'; status = 'deprecated'; policyType = 'EndpointSecurity'; supersededBy = @($script:LAPS4); previousVersions = @() }
            [pscustomobject]@{ oibId = $script:TPM4; name = 'Win - OIB - CP - Device Security - U - TPM - v4.0'; status = 'active'; policyType = 'CompliancePolicies'; supersededBy = @(); previousVersions = @() }
            [pscustomobject]@{ oibId = $script:PWD3; name = 'Win - OIB - Compliance - U - Password - v3.1'; status = 'deprecated'; policyType = 'CompliancePolicies'; supersededBy = @(); previousVersions = @() }
        )
    }
    $script:Release = ConvertFrom-CIPPOIBRelease -Tag 'windows-v4.0' -Paths $script:Paths -Manifest $script:Manifest

    function New-TestItem {
        param($Name, $Description = '', $Id = 'id-1')
        [pscustomobject]@{ Id = $Id; Name = $Name; Description = $Description; Type = 'Settings Catalog' }
    }
    function Compare-One {
        param($Name, $Description = '')
        Compare-CIPPOIBVersion -Items @(New-TestItem $Name $Description) -Release $script:Release -ExcludeMissing
    }
}

Describe 'ConvertFrom-CIPPOIBPolicyName' {
    It 'parses the standard naming' {
        $P = ConvertFrom-CIPPOIBPolicyName -Name 'Win - OIB - SC - Microsoft Edge - D - Security - v4.0'
        $P.IsOib | Should -BeTrue
        $P.Version | Should -Be '4.0'
        $P.BaseKey | Should -Be 'sc - microsoft edge - d - security'
        $P.BaseName | Should -Be 'Win - OIB - SC - Microsoft Edge - D - Security'
        $P.Suffix | Should -BeNullOrEmpty
    }

    It 'parses names without the D/U segment' {
        $P = ConvertFrom-CIPPOIBPolicyName -Name 'Win - OIB - WUfB Drivers - Ring 1 - Pilot - v3.0'
        $P.Version | Should -Be '3.0'
        $P.BaseKey | Should -Be 'wufb drivers - ring 1 - pilot'
    }

    It 'tolerates case, spacing and a suffix after the version' {
        $P = ConvertFrom-CIPPOIBPolicyName -Name '  win - oib -  SC - Microsoft Edge -  D - Security - v4.0 - Copy'
        $P.IsOib | Should -BeTrue
        $P.Version | Should -Be '4.0'
        $P.Suffix | Should -Be '- Copy'
        $P.BaseKey | Should -Be 'sc - microsoft edge - d - security'
        (ConvertFrom-CIPPOIBPolicyName -Name 'Win - OIB - SC - Edge - D - Security - v3.2 (1)').Suffix | Should -Be '(1)'
    }

    It 'takes the last version token and normalises a bare major version' {
        (ConvertFrom-CIPPOIBPolicyName -Name 'Win - OIB - SC - Thing - v1.0 - D - Other - v3.10').Version | Should -Be '3.10'
        (ConvertFrom-CIPPOIBPolicyName -Name 'Win - OIB - SC - Thing - D - Other - v4').Version | Should -Be '4.0'
    }

    It 'returns no version for an unversioned OIB-style name' {
        $P = ConvertFrom-CIPPOIBPolicyName -Name 'Win - OIB - SC - Something'
        $P.IsOib | Should -BeTrue
        $P.Version | Should -BeNullOrEmpty
        $P.BaseKey | Should -Be 'sc - something'
    }

    It 'rejects Win365, macOS and non-OIB names' {
        (ConvertFrom-CIPPOIBPolicyName -Name 'Win365 - OIB - Device Security - D - Connectivity Settings - v1.0').IsOib | Should -BeFalse
        (ConvertFrom-CIPPOIBPolicyName -Name 'MacOS - OIB - Firewall - D - Gatekeeper - v1.0').IsOib | Should -BeFalse
        (ConvertFrom-CIPPOIBPolicyName -Name 'Aspendora: Edge Hardening - OIB v4.0 picks').IsOib | Should -BeFalse
        (ConvertFrom-CIPPOIBPolicyName -Name $null).IsOib | Should -BeFalse
    }

    It 'reads the OIBID from a description' {
        (ConvertFrom-CIPPOIBPolicyName -Name 'x' -Description 'OIBID:24bfff77-81dc-4867-a8f8-ba8249cae404').OibId | Should -Be $script:TPM4
        (ConvertFrom-CIPPOIBPolicyName -Name 'x' -Description 'no id here').OibId | Should -BeNullOrEmpty
    }
}

Describe 'ConvertFrom-CIPPOIBRelease' {
    It 'takes Windows policy files only and adds the deprecated manifest entries' {
        $script:Release.Version | Should -Be '4.0'
        @($script:Release.Policies | Where-Object Status -EQ 'Active').Count | Should -Be 6
        @($script:Release.Policies | Where-Object Status -EQ 'Deprecated').Name | Should -Be @('Win - OIB - ES - Windows LAPS - D - LAPS Configuration - v3.1', 'Win - OIB - Compliance - U - Password - v3.1')
    }

    It 'carries OIBIDs, previous-version OIBIDs and resolves supersededBy to names' {
        $AV = $script:Release.Policies | Where-Object Name -Like '*AV Configuration*'
        $AV.OibId | Should -Be $script:AV4
        $AV.PreviousIds | Should -Be @($script:AV3)
        $AV.PolicyType | Should -Be 'SettingsCatalog'
        ($script:Release.Policies | Where-Object Name -Like '*LAPS*v3.1').SupersededBy | Should -Be @('Win - OIB - ES - Windows LAPS - D - LAPS Configuration - v4.0')
    }

    It 'works from file names alone when there is no manifest' {
        $R = ConvertFrom-CIPPOIBRelease -Tag 'windows-v3.8' -Paths $script:Paths -Manifest $null
        @($R.Policies).Count | Should -Be 6
        @($R.Policies | Where-Object OibId).Count | Should -Be 0
    }
}

Describe 'Compare-CIPPOIBVersion' {
    It 'reports a policy at the release version as Current (Info)' {
        $F = Compare-One 'Win - OIB - SC - Microsoft Edge - D - Security - v4.0'
        $F.State | Should -Be 'Current'
        $F.Severity | Should -Be 'Info'
        $F.Key | Should -Be 'Current|id-1'
    }

    It 'reports an older version as Outdated with from and to' {
        $F = Compare-One 'Win - OIB - SC - Microsoft Edge - D - Security - v3.2'
        $F.State | Should -Be 'Outdated'
        $F.Severity | Should -Be 'Warning'
        $F.CurrentVersion | Should -Be '3.2'
        $F.LatestVersion | Should -Be '4.0'
        $F.LatestName | Should -Be 'Win - OIB - SC - Microsoft Edge - D - Security - v4.0'
        $F.Key | Should -Be 'Outdated|id-1|3.2'
        $F.Message | Should -Match 'v3\.2 -> v4\.0'
    }

    It 'compares versions numerically (3.9 is older than 3.10)' {
        $R = [pscustomobject]@{ Tag = 'windows-v9.9'; Policies = @([pscustomobject]@{ Name = 'Win - OIB - SC - A - D - B - v3.10'; BaseKey = 'sc - a - d - b'; Version = '3.10'; PolicyType = 'SettingsCatalog'; Status = 'Active'; OibId = $null; PreviousIds = @(); SupersededBy = @() }) }
        (Compare-CIPPOIBVersion -Items @(New-TestItem 'Win - OIB - SC - A - D - B - v3.9') -Release $R -ExcludeMissing).State | Should -Be 'Outdated'
        (Compare-CIPPOIBVersion -Items @(New-TestItem 'Win - OIB - SC - A - D - B - v3.10') -Release $R -ExcludeMissing).State | Should -Be 'Current'
    }

    It 'matches a renamed policy by its previous-version OIBID as Outdated' {
        $F = Compare-One 'Win - OIB - ES - Defender AV (Contoso) - v3.3' "OIBID:$($script:AV3)"
        $F.State | Should -Be 'Outdated'
        $F.LatestName | Should -Be 'Win - OIB - ES - Defender Antivirus - D - AV Configuration - v4.0'
    }

    It 'matches a renamed policy by its current OIBID as Current' {
        (Compare-One 'Win - OIB - CP - TPM (renamed) - v4.0' "OIBID:$($script:TPM4)").State | Should -Be 'Current'
    }

    It 'reports a deprecated policy as Retired and names its replacement' {
        $F = Compare-One 'Win - OIB - ES - Windows LAPS - D - LAPS Configuration - v3.1'
        $F.State | Should -Be 'Retired'
        $F.Severity | Should -Be 'Warning'
        $F.Message | Should -Match 'Replaced by: Win - OIB - ES - Windows LAPS - D - LAPS Configuration - v4\.0'
    }

    It 'reports a deprecated policy with no replacement as Retired' {
        $F = Compare-One 'Win - OIB - Compliance - U - Password - v3.1'
        $F.State | Should -Be 'Retired'
        $F.Message | Should -Match 'no replacement'
    }

    It 'reports a policy that is not in the release at all as Retired' {
        $F = Compare-One 'Win - OIB - SC - Dropped Area - D - Old Thing - v3.0'
        $F.State | Should -Be 'Retired'
        $F.Message | Should -Match 'not in OIB windows-v4\.0'
    }

    It 'reports a newer-than-release version as Newer (Info)' {
        $F = Compare-One 'Win - OIB - SC - Microsoft Office - D - Updates - v3.1'
        $F.State | Should -Be 'Newer'
        $F.Severity | Should -Be 'Info'
    }

    It 'reports unversioned OIB-style names as Unknown (Info)' {
        (Compare-One 'Win - OIB - SC - Microsoft Edge - D - Security').State | Should -Be 'Unknown'
        (Compare-One 'Win - OIB - Custom Thing').State | Should -Be 'Unknown'
    }

    It 'lists release policies that are not present as Missing (Info), and can leave them out' {
        $F = Compare-CIPPOIBVersion -Items @(New-TestItem 'Win - OIB - SC - Microsoft Edge - D - Security - v3.2') -Release $script:Release
        $Missing = @($F | Where-Object State -EQ 'Missing')
        $Missing.Count | Should -Be 5
        @($Missing | Where-Object Severity -NE 'Info').Count | Should -Be 0
        $Missing.Name | Should -Not -Contain 'Win - OIB - SC - Microsoft Edge - D - Security - v4.0'
        $Missing.Key | Should -Contain 'Missing|cp - device security - u - tpm'
        @(Compare-CIPPOIBVersion -Items @() -Release $script:Release -ExcludeMissing).Count | Should -Be 0
    }

    It 'ignores non-OIB policies' {
        $Items = @((New-TestItem 'Win365 - OIB - Device Security - D - Connectivity Settings - v1.0'), (New-TestItem 'Aspendora: Office Security - OIB v4.0 picks'), $null)
        @(Compare-CIPPOIBVersion -Items $Items -Release $script:Release -ExcludeMissing).Count | Should -Be 0
    }
}

Describe 'Get-CIPPOIBLatestRelease' {
    BeforeAll {
        $script:Releases = @(
            [pscustomobject]@{ tag_name = 'macos-v1.0'; draft = $false; prerelease = $false; published_at = '2024-09-02T12:11:47Z'; html_url = 'u-mac' }
            [pscustomobject]@{ tag_name = 'windows-v3.8'; draft = $false; prerelease = $false; published_at = '2026-05-08T12:33:27Z'; html_url = 'u-38' }
            [pscustomobject]@{ tag_name = 'windows-v4.1'; draft = $false; prerelease = $true; published_at = '2026-10-30T00:00:00Z'; html_url = 'u-41' }
            [pscustomobject]@{ tag_name = 'windows-v4.0'; draft = $false; prerelease = $false; published_at = '2026-09-30T17:53:44Z'; html_url = 'u-40' }
            [pscustomobject]@{ tag_name = 'win365-v1.0'; draft = $false; prerelease = $false; published_at = '2024-09-02T12:36:10Z'; html_url = 'u-365' }
        )
        $script:CachedRow = {
            param($Hours)
            [pscustomobject]@{ Tag = 'windows-v3.8'; Version = '3.8'; PublishedAt = ''; Url = 'u-38'; FetchedAt = [datetime]::UtcNow.AddHours(-$Hours).ToString('o')
                Policies = (ConvertTo-Json -InputObject @($script:Release.Policies) -Depth 5 -Compress) }
        }
    }

    It 'serves a fresh cached copy without calling GitHub' {
        Mock Get-CIPPTable { @{} }
        Mock Get-CIPPAzDataTableEntity { & $script:CachedRow 1 }
        Mock Invoke-GitHubApiRequest { throw 'should not be called' }
        $R = Get-CIPPOIBLatestRelease
        $R.Tag | Should -Be 'windows-v3.8'
        $R.Stale | Should -BeFalse
        @($R.Policies).Count | Should -Be 8
        Should -Invoke Invoke-GitHubApiRequest -Times 0
    }

    It 'refreshes a day-old copy, picking the highest released windows-v tag' {
        Mock Get-CIPPTable { @{} }
        Mock Get-CIPPAzDataTableEntity { & $script:CachedRow 25 }
        Mock Invoke-GitHubApiRequest { $script:Releases }
        Mock Get-GitHubFileTree { [pscustomobject]@{ tree = @($script:Paths | ForEach-Object { [pscustomobject]@{ type = 'blob'; path = $_ } }) } }
        Mock Get-GitHubFileContents { [pscustomobject]@{ content = ($script:Manifest | ConvertTo-Json -Depth 10) } }
        Mock Add-CIPPAzDataTableEntity {}
        $R = Get-CIPPOIBLatestRelease
        $R.Tag | Should -Be 'windows-v4.0'
        $R.Url | Should -Be 'u-40'
        @($R.Policies | Where-Object Status -EQ 'Deprecated').Count | Should -Be 2
        Should -Invoke Get-GitHubFileTree -Times 1 -ParameterFilter { $Branch -eq 'windows-v4.0' }
        Should -Invoke Add-CIPPAzDataTableEntity -Times 1 -ParameterFilter { $Entity.RowKey -eq 'WindowsLatest' -and $Entity.Tag -eq 'windows-v4.0' }
    }

    It 'falls back to the stale cached copy when GitHub fails' {
        Mock Get-CIPPTable { @{} }
        Mock Get-CIPPAzDataTableEntity { & $script:CachedRow 48 }
        Mock Invoke-GitHubApiRequest { throw 'rate limited' }
        Mock Write-LogMessage {}
        $R = Get-CIPPOIBLatestRelease
        $R.Tag | Should -Be 'windows-v3.8'
        $R.Stale | Should -BeTrue
    }

    It 'throws when GitHub fails and nothing is cached' {
        Mock Get-CIPPTable { @{} }
        Mock Get-CIPPAzDataTableEntity { }
        Mock Invoke-GitHubApiRequest { throw 'rate limited' }
        { Get-CIPPOIBLatestRelease } | Should -Throw '*latest OIB release*'
    }
}

Describe 'Get-CIPPOIBDrift' {
    BeforeEach {
        Mock Get-CIPPOIBLatestRelease { $script:Release }
    }

    It 'collects only Win - OIB - tenant policies and records failed reads as errors' {
        Mock New-GraphGetRequest {
            switch -Wildcard ($uri) {
                '*configurationPolicies*' { @([pscustomobject]@{ id = 'a'; name = 'Win - OIB - SC - Microsoft Edge - D - Security - v3.2'; description = '' }, [pscustomobject]@{ id = 'b'; name = 'Bitlocker'; description = '' }) }
                '*deviceCompliancePolicies*' { @([pscustomobject]@{ id = 'c'; displayName = 'Win - OIB - Compliance - U - Password - v3.1'; description = '' }) }
                '*intents*' { throw 'Forbidden' }
                default { @() }
            }
        }
        $R = Get-CIPPOIBDrift -TenantFilter 'contoso.com' -ExcludeMissing
        $R.Scope | Should -Be 'contoso.com'
        $R.OibItemCount | Should -Be 2
        ($R.Findings | Sort-Object Id).State | Should -Be @('Outdated', 'Retired')
        $R.Summary.Outdated | Should -Be 1
        $R.Errors | Should -Be @('Endpoint Security (intent): denied')
    }

    It 'checks the template library in TemplateLibrary mode' {
        Mock Get-CIPPTable { @{} }
        Mock Get-CIPPAzDataTableEntity {
            @([pscustomobject]@{ RowKey = 't1'; Source = 'SkipToTheEndpoint/OpenIntuneBaseline'; JSON = (@{ Displayname = 'Win - OIB - CP - Device Security - U - TPM - v4.0'; Description = "OIBID:$($script:TPM4)"; Type = 'DeviceCompliancePolicies'; RAWJson = '{}' } | ConvertTo-Json -Compress) },
                [pscustomobject]@{ RowKey = 't2'; JSON = (@{ Displayname = 'CIPP: LAPS'; Type = 'Catalog'; RAWJson = '{}' } | ConvertTo-Json -Compress) })
        }
        $R = Get-CIPPOIBDrift -TemplateLibrary
        $R.Scope | Should -Be 'TemplateLibrary'
        $R.OibItemCount | Should -Be 1
        $R.Summary.Current | Should -Be 1
        $R.Summary.Missing | Should -Be 5
        $R.Errors | Should -BeNullOrEmpty
    }
}
