# SharePoint returns its sharing settings as bare enum integers. A record that says
# "SharePoint external sharing: 2" is not documentation - it is a number the reader has to
# go and look up, which is the thing these documents exist to prevent. The raw value is
# kept in parentheses so it still matches Microsoft's docs and any script output.

BeforeAll {
    # The maps and formatter, lifted verbatim from the Sharing section.
    $script:SharingCapability = @{
        '0' = 'Disabled - no external sharing'
        '1' = 'External users only (must sign in)'
        '2' = 'External users and anonymous guest links'
        '3' = 'Existing external users only'
    }
    $script:LinkType = @{
        '0' = 'None'; '1' = 'Direct - specific people'
        '2' = 'Internal - people in the organisation'; '3' = 'Anonymous - anyone with the link'
    }
    function Format-Enum($Map, $Value) {
        if ($null -eq $Value) { return '' }
        $Key = "$Value"
        if ($Map.ContainsKey($Key)) { return "$($Map[$Key]) ($Key)" }
        return $Key
    }
    function Format-AnonymousExpiry($Days) {
        if ([int]$Days -lt 0) { return 'Never expire' }
        return "$Days days"
    }
}

Describe 'Tenant overview sharing settings' {

    It 'translates the sharing capability a reader actually cares about' {
        # 2 is the permissive one - anonymous guest links. It must not render as "2".
        Format-Enum $script:SharingCapability 2 | Should -Be 'External users and anonymous guest links (2)'
        Format-Enum $script:SharingCapability 0 | Should -Be 'Disabled - no external sharing (0)'
    }

    It 'keeps the raw enum value visible for cross-referencing' {
        Format-Enum $script:SharingCapability 1 | Should -Match '\(1\)$'
        Format-Enum $script:LinkType 3 | Should -Match '\(3\)$'
    }

    It 'translates anonymous link types' {
        Format-Enum $script:LinkType 3 | Should -Be 'Anonymous - anyone with the link (3)'
    }

    It 'reads -1 as never, not as a negative number of days' {
        # SPO uses -1 as a sentinel. "Anonymous links expire (days): -1" reads as a bug.
        Format-AnonymousExpiry -1 | Should -Be 'Never expire'
        Format-AnonymousExpiry 30 | Should -Be '30 days'
    }

    It 'passes through an unknown enum rather than inventing a label' {
        # A value Microsoft adds later must not be silently mislabelled.
        Format-Enum $script:SharingCapability 9 | Should -Be '9'
    }

    It 'returns empty for a null value' {
        Format-Enum $script:SharingCapability $null | Should -Be ''
    }
}
