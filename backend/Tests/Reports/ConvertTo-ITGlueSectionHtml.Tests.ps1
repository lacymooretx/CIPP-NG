# IT Glue rejects the ENTIRE flexible-asset write with HTTP 422 if any single Textbox trait
# exceeds 64 kilobytes ("is too long, must not exceed 64 kilobytes" - verified live against
# the API: 43KB accepted, 108KB rejected). One oversized section therefore loses the whole
# client's documentation, not just that section.
#
# 3E NDT alone carries 105KB of raw settings JSON, so this is the normal path, not an edge
# case. These tests pin the two properties that matter: the output always fits, and any
# truncation is visible to whoever reads the record.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CippExtensions/Private/ITGlue/ConvertTo-ITGlueSectionHtml.ps1')

    # The real IT Glue ceiling. Nothing this function emits may cross it.
    $script:HardLimit = 65536

    function New-Section([int]$RowCount, [string]$CellText = 'Block credential stealing from the Windows local security authority subsystem') {
        $Rows = [System.Collections.Generic.List[object]]::new()
        for ($i = 1; $i -le $RowCount; $i++) {
            $Rows.Add(@("Defender ASR Baseline $i", 'windows10', $CellText, 'Enabled (Block)', 'SG-Intune-AllWorkstations'))
        }
        @{
            Key         = 'SettingsCatalog'
            Title       = 'Settings Catalog'
            Description = "$RowCount configured settings."
            Columns     = @('Policy', 'Platform', 'Setting', 'Value', 'Assigned To')
            Rows        = $Rows
            Empty       = 'No settings catalog policies are configured in this tenant.'
        }
    }
}

Describe 'ConvertTo-ITGlueSectionHtml' {

    It 'renders every row when the section fits' {
        $Html = ConvertTo-ITGlueSectionHtml -Section (New-Section 20)

        ([regex]::Matches($Html, '<tr>')).Count | Should -Be 21   # 20 body rows + header
        $Html | Should -Not -Match 'Truncated:'
        $Html.Length | Should -BeLessThan $script:HardLimit
    }

    It 'stays under the 64KB limit on a section far too large to fit' {
        # 2000 rows is ~430KB unbudgeted - the payload size that returned 422 live.
        $Html = ConvertTo-ITGlueSectionHtml -Section (New-Section 2000)
        $Html.Length | Should -BeLessThan $script:HardLimit
    }

    It 'states the truncation in the rendered output rather than silently dropping rows' {
        $Html = ConvertTo-ITGlueSectionHtml -Section (New-Section 2000)

        $Html | Should -Match 'Truncated:'
        $Html | Should -Match 'of 2000 rows'
        $Html | Should -Match 'open the full report in CIPP'
    }

    It 'reports the truncation to the caller so it reaches Collection Notes' {
        $Notes = [System.Collections.Generic.List[object]]::new()
        $null = ConvertTo-ITGlueSectionHtml -Section (New-Section 2000) -Truncated $Notes

        $Notes.Count | Should -Be 1
        $Notes[0].Section | Should -Be 'Settings Catalog'
        $Notes[0].Detail | Should -Match 'withheld to stay under the 64KB field limit'
    }

    It 'adds no note when nothing was withheld' {
        $Notes = [System.Collections.Generic.List[object]]::new()
        $null = ConvertTo-ITGlueSectionHtml -Section (New-Section 5) -Truncated $Notes
        $Notes.Count | Should -Be 0
    }

    It 'writes the empty-state sentence instead of an empty table' {
        # "No compliance policies" is documentation. A blank field is not.
        $Section = New-Section 0
        $Html = ConvertTo-ITGlueSectionHtml -Section $Section

        $Html | Should -Match 'No settings catalog policies are configured'
        $Html | Should -Not -Match '<table'
    }

    It 'HTML-encodes cell content so a policy name cannot inject markup' {
        $Section = New-Section 1
        $Section.Rows[0] = @('<script>alert(1)</script>', 'windows10', 'Setting & value', '"quoted"', 'SG-Test')
        $Html = ConvertTo-ITGlueSectionHtml -Section $Section

        $Html | Should -Not -Match '<script>'
        $Html | Should -Match '&lt;script&gt;'
        $Html | Should -Match 'Setting &amp; value'
    }

    It 'honours a smaller explicit budget' {
        $Html = ConvertTo-ITGlueSectionHtml -Section (New-Section 500) -MaxBytes 4000
        $Html.Length | Should -BeLessThan 4000
        $Html | Should -Match 'Truncated:'
    }

    It 'renders array cells as a joined list rather than a type name' {
        $Section = New-Section 1
        $Section.Rows[0] = @('Policy', 'windows10', 'Setting', @('One', 'Two', 'Three'), 'SG-Test')
        $Html = ConvertTo-ITGlueSectionHtml -Section $Section

        $Html | Should -Match 'One, Two, Three'
        $Html | Should -Not -Match 'System\.Object'
    }
}

Describe 'ConvertTo-ITGlueSectionHtml density' {
    # Density is not cosmetic here. Rendered at one styled <td> per cell, 3E NDT's real
    # settings catalog (207 rows) truncated at row 113 - 45% of the tenant's configuration
    # silently absent from its own documentation. Blank-repeat collapse plus table-level
    # styling brought the same section to ~30KB, complete. These tests keep it that way.

    It 'blanks a repeated leading cell but keeps the first occurrence' {
        $Rows = [System.Collections.Generic.List[object]]::new()
        $Rows.Add(@('ASR Default rules', 'windows10', 'Rule A', 'Audit'))
        $Rows.Add(@('ASR Default rules', 'windows10', 'Rule B', 'Block'))
        $Section = @{ Title = 'Settings Catalog'; Columns = @('Policy', 'Platform', 'Setting', 'Value'); Rows = $Rows; Empty = 'none' }

        $Html = ConvertTo-ITGlueSectionHtml -Section $Section

        # The policy name is written once, then collapsed on the repeat.
        ([regex]::Matches($Html, 'ASR Default rules')).Count | Should -Be 1
        $Html | Should -Match '<td></td><td></td><td>Rule B</td>'
        # Both settings still appear - collapsing must never drop content.
        $Html | Should -Match 'Rule A'
        $Html | Should -Match 'Rule B'
    }

    It 'does not collapse a cell once an earlier column has changed' {
        $Rows = [System.Collections.Generic.List[object]]::new()
        $Rows.Add(@('Policy One', 'windows10', 'Rule A'))
        $Rows.Add(@('Policy Two', 'windows10', 'Rule A'))
        $Section = @{ Title = 'S'; Columns = @('Policy', 'Platform', 'Setting'); Rows = $Rows; Empty = 'none' }

        $Html = ConvertTo-ITGlueSectionHtml -Section $Section

        # Platform repeats, but the policy changed first, so the run is broken and every
        # remaining cell on the row must be written out in full.
        $Html | Should -Match '<td>Policy Two</td><td>windows10</td><td>Rule A</td>'
    }

    It 'fits a realistically sized settings catalog without truncating' {
        # 207 rows is the real 3E NDT figure.
        $Rows = [System.Collections.Generic.List[object]]::new()
        for ($i = 1; $i -le 207; $i++) {
            $Rows.Add(@('ASR Default rules', 'windows10',
                    "Defender Attacksurfacereductionrules Blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem $i",
                    'Audit', 'All Licenced Users, All Devices'))
        }
        $Section = @{ Title = 'Settings Catalog'; Columns = @('Policy', 'Platform', 'Setting', 'Value', 'Assigned To'); Rows = $Rows; Empty = 'none' }

        $Notes = [System.Collections.Generic.List[object]]::new()
        $Html = ConvertTo-ITGlueSectionHtml -Section $Section -Truncated $Notes

        $Notes.Count | Should -Be 0
        $Html | Should -Not -Match 'Truncated:'
        $Html.Length | Should -BeLessThan 65536
    }
}
