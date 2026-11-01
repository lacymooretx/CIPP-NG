function Measure-CIPPTldExposure {
    <#
    .SYNOPSIS
        Counts message-trace rows that a *.TLD sender block would have stopped (inbound) or broken (outbound).
    .DESCRIPTION
        Inbound: the sender's domain is under a listed TLD and a recipient is in the tenant (accepted domains).
        Outbound: a recipient's domain is under a listed TLD and the sender is in the tenant - TABL sender blocks
        also stop users sending to blocked domains, and Microsoft rejects the whole message (every recipient) when
        one recipient matches. Exchange journal reports (MicrosoftExchange<guid>@ senders) are ignored.
        Rows are per recipient; Messages counts distinct MessageTraceId.
        With no AcceptedDomains, direction is decided by the TLD alone.
        Aspendora fork addition (Vikunja CIPP-30).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [Parameter(Mandatory)][string[]]$Tlds,
        [string[]]$AcceptedDomains = @(),
        [int]$Top = 10
    )

    $TldSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($T in $Tlds) { if ($T) { [void]$TldSet.Add(($T.Trim().TrimStart('*').TrimStart('.'))) } }
    $Accepted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($D in $AcceptedDomains) { if ($D) { [void]$Accepted.Add($D.Trim()) } }

    $GetDomain = {
        param($Address)
        $A = ([string]$Address).Trim().Trim('<', '>').TrimEnd('.')
        $At = $A.LastIndexOf('@')
        if ($At -lt 0) { return $null }
        $A.Substring($At + 1).ToLowerInvariant()
    }
    $GetTld = { param($Domain) if (-not $Domain) { return $null }; $Dot = $Domain.LastIndexOf('.'); if ($Dot -lt 0) { return $null }; $Domain.Substring($Dot + 1) }
    # A domain is internal when it is, or is a subdomain of, an accepted domain.
    $IsInternal = {
        param($Domain)
        if (-not $Domain -or $Accepted.Count -eq 0) { return $false }
        if ($Accepted.Contains($Domain)) { return $true }
        foreach ($Acc in $Accepted) { if ($Domain.EndsWith(".$Acc", [System.StringComparison]::OrdinalIgnoreCase)) { return $true } }
        return $false
    }

    $ByTld = @{}
    foreach ($T in $TldSet) { $ByTld[$T] = @{ Inbound = 0; Outbound = 0; InMsgs = [System.Collections.Generic.HashSet[string]]::new(); OutMsgs = [System.Collections.Generic.HashSet[string]]::new(); InDelivered = 0; InFiltered = 0; Senders = @{}; Recipients = @{}; InternalSenders = @{} } }
    $Scanned = 0
    $AllIn = [System.Collections.Generic.HashSet[string]]::new()
    $AllOut = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($Row in @($Rows)) {
        if ($null -eq $Row) { continue }
        $Scanned++
        $Sender = [string]$Row.SenderAddress
        if ($Sender -match '^microsoftexchange[0-9a-f]{32}@') { continue }
        $SenderDomain = & $GetDomain $Sender
        $RecipientDomain = & $GetDomain $Row.RecipientAddress
        $SenderTld = & $GetTld $SenderDomain
        $RecipientTld = & $GetTld $RecipientDomain
        $Id = [string]($Row.MessageTraceId ?? "$Sender|$($Row.Received)")
        $Status = [string]$Row.Status

        if ($SenderTld -and $TldSet.Contains($SenderTld) -and ($Accepted.Count -eq 0 -or (& $IsInternal $RecipientDomain))) {
            $B = $ByTld[$SenderTld]
            $B.Inbound++
            [void]$B.InMsgs.Add($Id); [void]$AllIn.Add($Id)
            if ($Status -eq 'Delivered') { $B.InDelivered++ } elseif ($Status -in @('FilteredAsSpam', 'Quarantined', 'Failed')) { $B.InFiltered++ }
            $B.Senders[$SenderDomain] = 1 + ($B.Senders[$SenderDomain] ?? 0)
        } elseif ($RecipientTld -and $TldSet.Contains($RecipientTld) -and ($Accepted.Count -eq 0 -or (& $IsInternal $SenderDomain))) {
            $B = $ByTld[$RecipientTld]
            $B.Outbound++
            [void]$B.OutMsgs.Add($Id); [void]$AllOut.Add($Id)
            $B.Recipients[$RecipientDomain] = 1 + ($B.Recipients[$RecipientDomain] ?? 0)
            $B.InternalSenders[$Sender.ToLowerInvariant()] = 1
        }
    }

    $TopOf = { param($Map, $Tld) @($Map.GetEnumerator() | Sort-Object -Property @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key' } | Select-Object -First $Top | ForEach-Object { [pscustomobject]@{ Domain = $_.Key; Tld = $Tld; Count = $_.Value } }) }

    $PerTld = foreach ($T in ($TldSet | Sort-Object)) {
        $B = $ByTld[$T]
        [pscustomobject]@{
            Tld                 = $T
            SenderEntry         = "*.$T"
            InboundRows         = $B.Inbound
            InboundMessages     = $B.InMsgs.Count
            InboundDelivered    = $B.InDelivered
            InboundFiltered     = $B.InFiltered
            OutboundRows        = $B.Outbound
            OutboundMessages    = $B.OutMsgs.Count
            InternalSenders     = $B.InternalSenders.Count
            TopSenderDomains    = & $TopOf $B.Senders $T
            TopRecipientDomains = & $TopOf $B.Recipients $T
        }
    }
    $PerTld = @($PerTld | Sort-Object -Property @{ Expression = { $_.InboundRows + $_.OutboundRows }; Descending = $true }, Tld)

    $AllSenders = @{}
    $AllRecipients = @{}
    foreach ($T in $TldSet) {
        foreach ($E in $ByTld[$T].Senders.GetEnumerator()) { $AllSenders[$E.Key] = $E.Value }
        foreach ($E in $ByTld[$T].Recipients.GetEnumerator()) { $AllRecipients[$E.Key] = $E.Value }
    }
    $Label = { param($Map) @($Map.GetEnumerator() | Sort-Object -Property @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key' } | Select-Object -First $Top | ForEach-Object { [pscustomobject]@{ Domain = $_.Key; Tld = (& $GetTld $_.Key); Count = $_.Value } }) }

    [pscustomobject]@{
        RowsScanned          = $Scanned
        InboundMessages      = $AllIn.Count
        OutboundMessages     = $AllOut.Count
        TldsWithTraffic      = @($PerTld | Where-Object { ($_.InboundRows + $_.OutboundRows) -gt 0 } | ForEach-Object Tld)
        ByTld                = $PerTld
        TopSenderDomains     = & $Label $AllSenders
        TopOutboundDomains   = & $Label $AllRecipients
    }
}
