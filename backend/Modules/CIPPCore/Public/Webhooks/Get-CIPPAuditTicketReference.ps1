function Get-CIPPAuditTicketReference {
    <#
    .SYNOPSIS
        Returns the ConnectWise ticket number an audit record says it was made for, or $null.
    .DESCRIPTION
        Aspendora fork addition (Vikunja MSP-3, approved by Lacy 2026-11-03). Our own changes set off security audit
        rules, and each one opened a ticket someone then closed by hand. A record qualifies only when both hold:

          1. The actor is ours: CIPPActorClass MSP or CIPP, as stamped by Get-CIPPAuditActorClass.
          2. The changed object's name or comment holds exactly one 'CW 60047' style token.

        Anything else returns $null, and the alert opens a ticket as usual. These are security alerts, so every doubtful
        case fails toward a ticket:
          - Only name and comment fields are read, never the whole record, so a number elsewhere cannot redirect it.
          - The 'CW' prefix is required. A bare '#561834' is often someone else's case number, as in the real rule that
            prompted this ('... (CW 60047)' with a comment naming 'SonicWall MSS #561834').
          - Two different ticket numbers are ambiguous and return $null.
        The caller still has to confirm the ticket is open and belongs to this client (Add-ConnectWiseTicketNote).
    .PARAMETER Data
        The audit record after Test-CIPPAuditLogRules has flattened it.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Data
    )

    if ([string]$Data.CIPPActorIsMSP -ne 'True' -or [string]$Data.CIPPActorClass -notin @('MSP', 'CIPP')) { return $null }

    $NameFields = @('Name', 'Identity', 'DisplayName', 'Comment', 'Comments', 'Description', 'Justification', 'Reason')
    $Values = [System.Collections.Generic.List[string]]::new()
    foreach ($Parameter in @(try { $Data.CIPPParameters | ConvertFrom-Json -ErrorAction Stop } catch { @() })) {
        if ($Parameter -and [string]$Parameter.Name -in $NameFields) { $Values.Add([string]$Parameter.Value) }
    }
    foreach ($Property in @(try { $Data.CIPPModifiedProperties | ConvertFrom-Json -ErrorAction Stop } catch { @() })) {
        if ($Property -and [string]$Property.Name -in $NameFields) { $Values.Add([string]$Property.NewValue) }
    }

    # The regex object rather than -match, so $Matches is left alone for the caller.
    $Tickets = @(
        foreach ($Value in $Values) {
            foreach ($Found in [regex]::Matches($Value, '(?i)(?<![a-z0-9])CW[\s_-]*#?\s*(\d{5,7})(?!\d)')) { [int]$Found.Groups[1].Value }
        }
    ) | Select-Object -Unique
    if (@($Tickets).Count -ne 1) { return $null }
    return @($Tickets)[0]
}
