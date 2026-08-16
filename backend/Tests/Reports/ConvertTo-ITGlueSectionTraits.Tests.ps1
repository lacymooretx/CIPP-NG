# This mapping shipped a bug that failed every tenant in production, so it gets its own
# tests. In PowerShell `@($Hashtable['MissingKey'])` is a ONE-ELEMENT array containing
# $null, not an empty array. The continuation-field lookup used that form, so every section
# without continuation fields - which is all of them but Settings Catalog - ended up
# assigning $Traits[$null] and threw "Index operation failed; the array index evaluated to
# null". All 9 tenants logged it; not one Intune record was written.
#
# The renderer's own tests all passed, because the bug was in the glue between the renderer
# and the trait names. That is what these cover.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CippExtensions/Private/ITGlue/ConvertTo-ITGlueSectionHtml.ps1')
    . (Join-Path $RepoRoot 'Modules/CippExtensions/Private/ITGlue/ConvertTo-ITGlueSectionTraits.ps1')

    # The real maps from Sync-ITGlueIntuneConfig.
    $script:TraitMap = @{
        'ConfigurationProfiles'    = 'configuration-profiles'
        'SettingsCatalog'          = 'settings-catalog'
        'CompliancePolicies'       = 'compliance-policies'
        'SecurityBaselines'        = 'security-baselines-and-app-protection'
        'UpdateRings'              = 'update-rings'
        'AppsAndScripts'           = 'apps-and-scripts'
        'Enrollment'               = 'enrollment-and-autopilot'
        'RBAC'                     = 'rbac-and-scope-tags'
        'AdditionalConfigurations' = 'additional-configurations'
    }
    $script:OverflowMap = @{
        'SettingsCatalog' = @('settings-catalog-continued', 'settings-catalog-continued-2')
    }

    function New-TestSection([string]$Key, [string]$Title, [int]$RowCount) {
        $Rows = [System.Collections.Generic.List[object]]::new()
        for ($i = 1; $i -le $RowCount; $i++) {
            $Rows.Add(@("Policy $i", 'windows10', "Some setting name number $i", 'Enabled', 'SG-All'))
        }
        @{ Key = $Key; Title = $Title; Description = "$RowCount rows."
            Columns = @('Policy', 'Platform', 'Setting', 'Value', 'Assigned To'); Rows = $Rows; Empty = 'Nothing configured.'
        }
    }
}

Describe 'ConvertTo-ITGlueSectionTraits' {

    It 'maps a section with no continuation fields without throwing' {
        # The exact production failure: RBAC has no entry in OverflowMap.
        $Sections = @((New-TestSection 'RBAC' 'RBAC and Scope Tags' 3))

        { ConvertTo-ITGlueSectionTraits -Sections $Sections -TraitMap $script:TraitMap -OverflowMap $script:OverflowMap } |
            Should -Not -Throw
    }

    It 'produces no null trait names' {
        # $Traits[$null] was the actual crash. No key may ever be null or empty.
        $Sections = @(
            (New-TestSection 'ConfigurationProfiles' 'Configuration Profiles' 5),
            (New-TestSection 'RBAC' 'RBAC and Scope Tags' 5),
            (New-TestSection 'AdditionalConfigurations' 'Additional Configurations' 5)
        )
        $Traits = ConvertTo-ITGlueSectionTraits -Sections $Sections -TraitMap $script:TraitMap -OverflowMap $script:OverflowMap

        foreach ($Key in $Traits.Keys) {
            $Key | Should -Not -BeNullOrEmpty
            $Key | Should -BeOfType [string]
        }
    }

    It 'writes exactly one trait for a section with no continuation fields' {
        $Sections = @((New-TestSection 'CompliancePolicies' 'Compliance Policies' 4))
        $Traits = ConvertTo-ITGlueSectionTraits -Sections $Sections -TraitMap $script:TraitMap -OverflowMap $script:OverflowMap

        $Traits.Keys.Count | Should -Be 1
        $Traits.ContainsKey('compliance-policies') | Should -BeTrue
    }

    It 'fills continuation traits for a section that needs them' {
        $Sections = @((New-TestSection 'SettingsCatalog' 'Settings Catalog' 900))
        $Traits = ConvertTo-ITGlueSectionTraits -Sections $Sections -TraitMap $script:TraitMap -OverflowMap $script:OverflowMap

        $Traits.ContainsKey('settings-catalog') | Should -BeTrue
        $Traits.ContainsKey('settings-catalog-continued') | Should -BeTrue
        $Traits.ContainsKey('settings-catalog-continued-2') | Should -BeTrue
        $Traits['settings-catalog-continued'] | Should -Not -BeNullOrEmpty
    }

    It 'blanks unused continuation traits so a shrinking tenant leaves no stale rows' {
        $Sections = @((New-TestSection 'SettingsCatalog' 'Settings Catalog' 3))
        $Traits = ConvertTo-ITGlueSectionTraits -Sections $Sections -TraitMap $script:TraitMap -OverflowMap $script:OverflowMap

        # Present, and empty - not absent, which would leave last run's content in IT Glue.
        $Traits.ContainsKey('settings-catalog-continued') | Should -BeTrue
        $Traits['settings-catalog-continued'] | Should -Be ''
        $Traits['settings-catalog-continued-2'] | Should -Be ''
    }

    It 'maps a full nine-section model to the expected trait names' {
        $Sections = @($script:TraitMap.Keys | ForEach-Object { New-TestSection $_ $_ 2 })
        $Traits = ConvertTo-ITGlueSectionTraits -Sections $Sections -TraitMap $script:TraitMap -OverflowMap $script:OverflowMap

        # 9 sections + 2 continuation fields.
        $Traits.Keys.Count | Should -Be 11
        foreach ($Expected in $script:TraitMap.Values) { $Traits.ContainsKey($Expected) | Should -BeTrue }
    }

    It 'skips unknown sections rather than inventing a trait for them' {
        $Sections = @((New-TestSection 'SomethingNew' 'Future Section' 2))
        $Traits = ConvertTo-ITGlueSectionTraits -Sections $Sections -TraitMap $script:TraitMap -OverflowMap $script:OverflowMap
        $Traits.Keys.Count | Should -Be 0
    }

    It 'tolerates a null section list and null elements' {
        { ConvertTo-ITGlueSectionTraits -Sections $null -TraitMap $script:TraitMap } | Should -Not -Throw
        { ConvertTo-ITGlueSectionTraits -Sections @($null) -TraitMap $script:TraitMap } | Should -Not -Throw
    }

    It 'works with no OverflowMap supplied at all' {
        $Sections = @((New-TestSection 'SettingsCatalog' 'Settings Catalog' 5))
        { ConvertTo-ITGlueSectionTraits -Sections $Sections -TraitMap $script:TraitMap } | Should -Not -Throw
    }

    It 'collects truncation notes from the sections it renders' {
        $Notes = [System.Collections.Generic.List[object]]::new()
        $Sections = @((New-TestSection 'CompliancePolicies' 'Compliance Policies' 20000))
        $null = ConvertTo-ITGlueSectionTraits -Sections $Sections -TraitMap $script:TraitMap -OverflowMap $script:OverflowMap -Truncated $Notes

        $Notes.Count | Should -Be 1
        $Notes[0].Section | Should -Be 'Compliance Policies'
    }
}

Describe 'ConvertTo-ITGlueSectionTraits with a single continuation field' {
    # The Intune document has TWO continuation fields; the Identity document has ONE. That
    # difference alone broke production: `$x = if (...) { @($map[$key]) }` sends the array
    # through the pipeline, which UNROLLS a single-element array to its element. The
    # one-entry list became a bare string, $ContinuationFields[0] returned its first
    # CHARACTER, and the traits hashtable gained a key 'c' of type [char] - which
    # ConvertTo-Json rejects with "Keys must be strings", failing all 9 tenants.
    #
    # Every existing test used the two-entry Intune map and passed throughout.

    BeforeAll {
        $script:OneField = @{ 'ConditionalAccess' = @('conditional-access-policies-continued') }
        $script:OneMap = @{ 'ConditionalAccess' = 'conditional-access-policies' }
    }

    It 'produces only string keys' {
        $Traits = ConvertTo-ITGlueSectionTraits -Sections @((New-TestSection 'ConditionalAccess' 'CA' 3)) `
            -TraitMap $script:OneMap -OverflowMap $script:OneField

        foreach ($Key in $Traits.Keys) {
            $Key | Should -BeOfType [string] -Because "a [char] key means the field list was unrolled to a string"
        }
    }

    It 'names the continuation trait in full, not by its first character' {
        $Traits = ConvertTo-ITGlueSectionTraits -Sections @((New-TestSection 'ConditionalAccess' 'CA' 3)) `
            -TraitMap $script:OneMap -OverflowMap $script:OneField

        $Traits.ContainsKey('conditional-access-policies-continued') | Should -BeTrue
        $Traits.ContainsKey('c') | Should -BeFalse
    }

    It 'produces a payload ConvertTo-Json accepts' {
        # The exact failure mode: a non-string key makes the whole IT Glue write throw.
        $Traits = ConvertTo-ITGlueSectionTraits -Sections @((New-TestSection 'ConditionalAccess' 'CA' 900)) `
            -TraitMap $script:OneMap -OverflowMap $script:OneField
        $Payload = @{ data = @{ type = 'flexible-assets'; attributes = @{ traits = $Traits } } }

        { $Payload | ConvertTo-Json -Depth 20 -Compress } | Should -Not -Throw
    }
}
