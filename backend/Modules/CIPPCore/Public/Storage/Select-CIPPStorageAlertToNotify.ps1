function Select-CIPPStorageAlertToNotify {
    <#
    .SYNOPSIS
        Decide which storage findings should raise a notification now, given what was
        already raised before.
    .DESCRIPTION
        CIPP's built-in repeat suppression (Write-AlertTrace) keys on tenant + cmdlet +
        CALENDAR DATE. Within a day it correctly stays quiet, but the partition key rolls
        over at midnight, so an unchanged finding alerts again tomorrow. A mailbox sitting
        at 94% for three weeks produces twenty-one tickets - which is how CIPP generated 44
        non-actionable ConnectWise tickets before, and why the operator stopped trusting it.

        This adds the missing dimension: a finding is notified once, then not again until
        either the re-notify window elapses or it gets materially worse. "Materially worse"
        is a band change (85 -> 90 -> 95), not a percentage point, so a mailbox drifting
        from 91% to 92% stays quiet.

        A finding that has RESOLVED is dropped from state silently rather than announced.
        A "good news" ticket is still a ticket somebody has to close.

        Pure: takes prior state, returns what to send and the new state. No tables, no
        clock - the caller supplies Now - so the suppression rules can actually be tested,
        which is the part that matters when the failure mode is "too quiet".

    .PARAMETER Findings
        Current findings: @( @{ Key; Band; Message } ). Key identifies the thing (a mailbox,
        a tenant projection); Band is an ordinal severity that only moves in steps.
    .PARAMETER Prior
        Previous state: @{ Key = @{ Band = <int>; LastNotified = <ISO8601 string> } }.
    .PARAMETER Now
        Current time.
    .PARAMETER ReNotifyDays
        How long an unchanged finding stays suppressed.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][AllowNull()]$Findings,
        [Parameter(Mandatory = $false)][AllowNull()]$Prior,
        [Parameter(Mandatory = $true)][datetime]$Now,
        [int]$ReNotifyDays = 14
    )

    $PriorMap = @{}
    if ($Prior) {
        foreach ($Key in @($Prior.Keys)) { $PriorMap[[string]$Key] = $Prior[$Key] }
    }

    $Notify = [System.Collections.Generic.List[object]]::new()
    $NewState = @{}

    foreach ($Finding in @($Findings)) {
        if (-not $Finding -or -not $Finding.Key) { continue }
        $Key = [string]$Finding.Key
        $Band = [int]($Finding.Band ?? 0)

        $Previous = $PriorMap[$Key]
        $ShouldNotify = $false
        $Reason = $null

        if (-not $Previous) {
            $ShouldNotify = $true
            $Reason = 'new'
        } else {
            $PrevBand = [int]($Previous.Band ?? 0)
            if ($Band -gt $PrevBand) {
                $ShouldNotify = $true
                $Reason = 'worsened'
            } else {
                $Last = $null
                try { $Last = [datetime]::Parse([string]$Previous.LastNotified, [cultureinfo]::InvariantCulture) } catch {}
                # Unparseable or missing timestamp means we cannot prove it was notified
                # recently. Notify: a duplicate ticket is recoverable, a silently dropped
                # 95%-full mailbox is not.
                if (-not $Last -or ($Now - $Last).TotalDays -ge $ReNotifyDays) {
                    $ShouldNotify = $true
                    $Reason = if ($Last) { 'reminder' } else { 'unknown-last-notified' }
                }
            }
        }

        if ($ShouldNotify) {
            $Notify.Add([pscustomobject]@{
                    Key     = $Key
                    Band    = $Band
                    Message = [string]$Finding.Message
                    Reason  = $Reason
                })
            $NewState[$Key] = @{ Band = $Band; LastNotified = $Now.ToString('o') }
        } else {
            # Carry the original notification time forward. Refreshing it on every quiet
            # run would push the reminder permanently into the future and the finding would
            # never be raised again.
            $NewState[$Key] = @{ Band = $Band; LastNotified = [string]$Previous.LastNotified }
        }
    }

    # Keys absent from $NewState are resolved findings and drop out of state here.
    return [pscustomobject]@{
        Notify   = @($Notify)
        State    = $NewState
        Resolved = @(@($PriorMap.Keys) | Where-Object { -not $NewState.ContainsKey($_) })
    }
}
