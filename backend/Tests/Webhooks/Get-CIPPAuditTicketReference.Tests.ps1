# Aspendora fork (Vikunja MSP-3): when an audit alert for our own change may become a note on a ConnectWise ticket.
# These are security alerts, so each doubtful case must return nothing and let the alert open a ticket.
BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Webhooks/Get-CIPPAuditTicketReference.ps1')

    function New-Record {
        param($Class = 'MSP', $IsMsp = 'True', $Parameters, $Modified)
        [pscustomobject]@{
            CIPPActorClass         = $Class
            CIPPActorIsMSP         = $IsMsp
            CIPPParameters         = if ($null -ne $Parameters) { ConvertTo-Json -Compress -Depth 5 -InputObject @($Parameters) } else { $null }
            CIPPModifiedProperties = if ($null -ne $Modified) { ConvertTo-Json -Compress -Depth 5 -InputObject @($Modified) } else { $null }
        }
    }
    function P { param($Name, $Value) @{ Name = $Name; Value = $Value } }
}

Describe 'Get-CIPPAuditTicketReference' {
    Context 'the real record that prompted this' {
        It 'finds CW 60047 in the rule name and ignores the vendor case number in the comment' {
            $Record = New-Record -Parameters @(
                (P 'Name' 'Aspendora - Route shared mailboxes via Avanan (CW 60047)')
                (P 'Comments' 'Temporary: Remove once SonicWall MSS #561834 is fixed. Added 2026-11-02 by Aspendora.')
                (P 'Priority' '4')
            )
            Get-CIPPAuditTicketReference -Data $Record | Should -Be 60047
        }

        It 'returns nothing for the role grant, which has no name or comment to carry a ticket' {
            $Record = New-Record -Modified @(@{ Name = 'Role.DisplayName'; NewValue = 'Global Administrator'; OldValue = '' })
            Get-CIPPAuditTicketReference -Data $Record | Should -BeNullOrEmpty
        }
    }

    Context 'the token' {
        It 'accepts <Text>' -ForEach @(
            @{ Text = 'CW 60047' }, @{ Text = 'CW #60047' }, @{ Text = 'CW#60047' }, @{ Text = 'cw60047' }
            @{ Text = 'see CW-60047 for detail' }, @{ Text = '(CW_60047)' }, @{ Text = 'CW 1234567' }
        ) {
            Get-CIPPAuditTicketReference -Data (New-Record -Parameters @(P 'Name' $Text)) | Should -BeIn @(60047, 1234567)
        }

        It 'refuses <Text>' -ForEach @(
            @{ Text = '#60047' }, @{ Text = '60047' }, @{ Text = 'MSS #561834' }, @{ Text = 'CW 1234' }
            @{ Text = 'CW 12345678' }, @{ Text = 'MCW 60047' }, @{ Text = 'INC60047' }
        ) {
            Get-CIPPAuditTicketReference -Data (New-Record -Parameters @(P 'Name' $Text)) | Should -BeNullOrEmpty
        }

        It 'refuses two different tickets as ambiguous' {
            $Record = New-Record -Parameters @((P 'Name' 'Rule (CW 60047)'), (P 'Comments' 'replaces CW 59999'))
            Get-CIPPAuditTicketReference -Data $Record | Should -BeNullOrEmpty
        }

        It 'accepts the same ticket named twice' {
            $Record = New-Record -Parameters @((P 'Name' 'Rule (CW 60047)'), (P 'Comments' 'for CW #60047'))
            Get-CIPPAuditTicketReference -Data $Record | Should -Be 60047
        }
    }

    Context 'where it may come from' {
        It 'reads <Field>' -ForEach @(
            @{ Field = 'Name' }, @{ Field = 'Identity' }, @{ Field = 'DisplayName' }, @{ Field = 'Comment' }
            @{ Field = 'Comments' }, @{ Field = 'Description' }, @{ Field = 'Justification' }, @{ Field = 'Reason' }
        ) {
            Get-CIPPAuditTicketReference -Data (New-Record -Parameters @(P $Field 'CW 60047')) | Should -Be 60047
        }

        It 'reads an Entra display name' {
            $Record = New-Record -Modified @(@{ Name = 'DisplayName'; NewValue = '["Policy (CW 60047)"]'; OldValue = '' })
            Get-CIPPAuditTicketReference -Data $Record | Should -Be 60047
        }

        It 'ignores the old value of an Entra display name' {
            $Record = New-Record -Modified @(@{ Name = 'DisplayName'; NewValue = 'Policy'; OldValue = 'Policy (CW 60047)' })
            Get-CIPPAuditTicketReference -Data $Record | Should -BeNullOrEmpty
        }

        It 'ignores a token in any other parameter' {
            $Record = New-Record -Parameters @(P 'SetHeaderValue' 'CW 60047')
            Get-CIPPAuditTicketReference -Data $Record | Should -BeNullOrEmpty
        }
    }

    Context 'the actor' {
        It 'accepts a CIPP app-only actor' {
            Get-CIPPAuditTicketReference -Data (New-Record -Class 'CIPP' -Parameters @(P 'Name' 'CW 60047')) | Should -Be 60047
        }

        It 'refuses <Class>' -ForEach @(
            @{ Class = 'Tenant'; IsMsp = 'False' }, @{ Class = 'App'; IsMsp = 'False' }
            @{ Class = 'OtherPartner'; IsMsp = 'False' }, @{ Class = 'Microsoft'; IsMsp = 'False' }
        ) {
            Get-CIPPAuditTicketReference -Data (New-Record -Class $Class -IsMsp $IsMsp -Parameters @(P 'Name' 'CW 60047')) | Should -BeNullOrEmpty
        }

        It 'refuses a record never classified' {
            $Record = [pscustomobject]@{ CIPPParameters = (ConvertTo-Json -Compress -InputObject @(@{ Name = 'Name'; Value = 'CW 60047' })) }
            Get-CIPPAuditTicketReference -Data $Record | Should -BeNullOrEmpty
        }

        It 'refuses when the two actor fields disagree' {
            Get-CIPPAuditTicketReference -Data (New-Record -Class 'MSP' -IsMsp 'False' -Parameters @(P 'Name' 'CW 60047')) | Should -BeNullOrEmpty
        }
    }

    Context 'unreadable records' {
        It 'returns nothing for bad JSON' {
            $Record = [pscustomobject]@{ CIPPActorClass = 'MSP'; CIPPActorIsMSP = 'True'; CIPPParameters = '{nope'; CIPPModifiedProperties = 'also nope' }
            Get-CIPPAuditTicketReference -Data $Record | Should -BeNullOrEmpty
        }

        It 'returns nothing when there are no parameters' {
            Get-CIPPAuditTicketReference -Data (New-Record) | Should -BeNullOrEmpty
        }
    }
}
