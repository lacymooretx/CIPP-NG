# The idiom this replaces - `$Value -in @($true,'true',1,'1','yes','on')` - was wrong in a way that
# read as correct. `-in` compares as the COLLECTION's element type, so with $true in the list
# PowerShell coerces the right-hand side to boolean and EVERY non-empty string is true:
# 'false', 'no', 'off' and '0' all returned True. A caller turning a flag off turned it on.
#
# It was live in 24 places across 14 fork endpoints, including AllowRemoveAll on the Cloud PC
# policy assign path, where "false" reading as true would have authorised unassigning a
# provisioning policy from every group in the tenant.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')
}

Describe 'ConvertTo-CIPPBoolean' {
    It 'treats <_> as true' -ForEach @('true', 'True', 'TRUE', '1', 'yes', 'on', ' true ', 'y', 't') {
        ConvertTo-CIPPBoolean -Value $_ | Should -BeTrue
    }

    It 'treats <_> as false - the case the old idiom got backwards' -ForEach @('false', 'False', 'FALSE', '0', 'no', 'off', ' false ', 'n', 'f') {
        ConvertTo-CIPPBoolean -Value $_ | Should -BeFalse
    }

    It 'passes real booleans straight through' {
        ConvertTo-CIPPBoolean -Value $true | Should -BeTrue
        ConvertTo-CIPPBoolean -Value $false | Should -BeFalse
    }

    It 'treats numbers numerically, not by emptiness' {
        ConvertTo-CIPPBoolean -Value 1 | Should -BeTrue
        ConvertTo-CIPPBoolean -Value 0 | Should -BeFalse
        ConvertTo-CIPPBoolean -Value 2 | Should -BeTrue
    }

    It 'returns the default for null, empty and unparseable input' {
        ConvertTo-CIPPBoolean -Value $null | Should -BeFalse
        ConvertTo-CIPPBoolean -Value '' | Should -BeFalse
        ConvertTo-CIPPBoolean -Value 'maybe' | Should -BeFalse
        # An unparseable flag behaves like an absent one, never like "on".
        ConvertTo-CIPPBoolean -Value 'maybe' -Default $true | Should -BeTrue
        ConvertTo-CIPPBoolean -Value $null -Default $true | Should -BeTrue
    }

    It 'demonstrates the bug it replaces, so nobody reintroduces the idiom' {
        $OldTruthy = @($true, 'true', 'True', 1, '1', 'yes', 'on')
        # This is what the old code did, and why it was wrong:
        ('false' -in $OldTruthy) | Should -BeTrue
        # This is what it should have done:
        ConvertTo-CIPPBoolean -Value 'false' | Should -BeFalse
    }
}
