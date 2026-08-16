# Repeat suppression for storage alerts.
#
# This exists because CIPP once produced 44 non-actionable ConnectWise tickets and the team
# stopped trusting its alerts. The built-in suppression keys on the calendar date, so an
# unchanged finding re-alerts every morning; a mailbox at 94% for three weeks is 21 tickets.
#
# The failure modes are opposite and both bad: too loud recreates the flood, too quiet drops
# a mailbox that is about to stop receiving mail. Both directions are tested.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Storage/Select-CIPPStorageAlertToNotify.ps1')

    $script:Now = [datetime]::Parse('2026-08-16T12:00:00Z', [cultureinfo]::InvariantCulture).ToUniversalTime()
    function F($Key, $Band) { @{ Key = $Key; Band = $Band; Message = "$Key at band $Band" } }
    function Prior($Key, $Band, $DaysAgo) {
        @{ $Key = @{ Band = $Band; LastNotified = $script:Now.AddDays(-$DaysAgo).ToString('o') } }
    }
}

Describe 'Select-CIPPStorageAlertToNotify' {

    It 'notifies a finding that has never been seen' {
        $R = Select-CIPPStorageAlertToNotify -Findings @((F 'Mailbox:a@x.com' 85)) -Prior @{} -Now $script:Now
        $R.Notify.Count | Should -Be 1
        $R.Notify[0].Reason | Should -Be 'new'
    }

    It 'stays quiet on an unchanged finding inside the window' {
        # The whole point: this is the day-2 case that used to make a second ticket.
        $R = Select-CIPPStorageAlertToNotify -Findings @((F 'Mailbox:a@x.com' 85)) `
            -Prior (Prior 'Mailbox:a@x.com' 85 1) -Now $script:Now -ReNotifyDays 14
        $R.Notify.Count | Should -Be 0
    }

    It 'stays quiet for the whole window, not just one day' {
        $R = Select-CIPPStorageAlertToNotify -Findings @((F 'Mailbox:a@x.com' 85)) `
            -Prior (Prior 'Mailbox:a@x.com' 85 13) -Now $script:Now -ReNotifyDays 14
        $R.Notify.Count | Should -Be 0
    }

    It 'raises a reminder once the window elapses' {
        # Suppression must not be permanent - a mailbox still at 94% after a fortnight is
        # not resolved, it is ignored.
        $R = Select-CIPPStorageAlertToNotify -Findings @((F 'Mailbox:a@x.com' 85)) `
            -Prior (Prior 'Mailbox:a@x.com' 85 14) -Now $script:Now -ReNotifyDays 14
        $R.Notify.Count | Should -Be 1
        $R.Notify[0].Reason | Should -Be 'reminder'
    }

    It 'breaks suppression immediately when the finding gets materially worse' {
        $R = Select-CIPPStorageAlertToNotify -Findings @((F 'Mailbox:a@x.com' 95)) `
            -Prior (Prior 'Mailbox:a@x.com' 90 1) -Now $script:Now
        $R.Notify.Count | Should -Be 1
        $R.Notify[0].Reason | Should -Be 'worsened'
    }

    It 'does not re-notify when the finding improves' {
        # Dropping 95 -> 90 is good news, and good news should not make a ticket.
        $R = Select-CIPPStorageAlertToNotify -Findings @((F 'Mailbox:a@x.com' 90)) `
            -Prior (Prior 'Mailbox:a@x.com' 95 1) -Now $script:Now
        $R.Notify.Count | Should -Be 0
    }

    It 'does not push the reminder deadline forward on quiet runs' {
        # The subtle one. If a suppressed run refreshed LastNotified, the window would reset
        # every day and the reminder would never fire - suppression would become permanent
        # silence, which is the dangerous failure, not the annoying one.
        $State = Prior 'Mailbox:a@x.com' 85 10
        $Original = $State['Mailbox:a@x.com'].LastNotified
        for ($Day = 0; $Day -lt 3; $Day++) {
            $R = Select-CIPPStorageAlertToNotify -Findings @((F 'Mailbox:a@x.com' 85)) `
                -Prior $State -Now $script:Now.AddDays($Day) -ReNotifyDays 14
            $State = $R.State
        }
        $State['Mailbox:a@x.com'].LastNotified | Should -Be $Original
        # ...and on day 14 from the ORIGINAL notification it fires.
        $R = Select-CIPPStorageAlertToNotify -Findings @((F 'Mailbox:a@x.com' 85)) `
            -Prior $State -Now $script:Now.AddDays(4) -ReNotifyDays 14
        $R.Notify.Count | Should -Be 1
    }

    It 'drops resolved findings from state without announcing them' {
        $R = Select-CIPPStorageAlertToNotify -Findings @() -Prior (Prior 'Mailbox:a@x.com' 85 1) -Now $script:Now
        $R.Notify.Count | Should -Be 0
        $R.State.Keys.Count | Should -Be 0
        $R.Resolved | Should -Contain 'Mailbox:a@x.com'
    }

    It 'notifies when the stored timestamp is unusable rather than swallowing the finding' {
        # Cannot prove it was already sent. A duplicate ticket is recoverable; a silently
        # dropped 95%-full mailbox is not.
        $R = Select-CIPPStorageAlertToNotify -Findings @((F 'Mailbox:a@x.com' 85)) `
            -Prior @{ 'Mailbox:a@x.com' = @{ Band = 85; LastNotified = 'not-a-date' } } -Now $script:Now
        $R.Notify.Count | Should -Be 1
        $R.Notify[0].Reason | Should -Be 'unknown-last-notified'
    }

    It 'tracks each finding independently' {
        $Prior = @{
            'Mailbox:a@x.com' = @{ Band = 85; LastNotified = $script:Now.AddDays(-1).ToString('o') }
            'Mailbox:b@x.com' = @{ Band = 85; LastNotified = $script:Now.AddDays(-1).ToString('o') }
        }
        $R = Select-CIPPStorageAlertToNotify -Now $script:Now -Prior $Prior -Findings @(
            (F 'Mailbox:a@x.com' 85)   # unchanged  -> quiet
            (F 'Mailbox:b@x.com' 95)   # worsened   -> notify
            (F 'Mailbox:c@x.com' 85)   # new        -> notify
        )
        @($R.Notify | ForEach-Object { $_.Key }) | Should -Be @('Mailbox:b@x.com', 'Mailbox:c@x.com')
    }

    It 'handles null findings and null prior state' {
        $R = Select-CIPPStorageAlertToNotify -Findings $null -Prior $null -Now $script:Now
        $R.Notify.Count | Should -Be 0
        $R.State.Keys.Count | Should -Be 0
    }
}
