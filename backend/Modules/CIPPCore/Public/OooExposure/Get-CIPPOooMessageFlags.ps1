function Get-CIPPOooMessageFlags {
    <#
    .SYNOPSIS
        Flags what an external auto-reply hands an attacker: contacts, phone numbers, travel, return dates, titles, finance cues.
    .DESCRIPTION
        Pure function (no API calls) so the rules can be unit tested. The HTML message is reduced to plain text, then:
          InternalEmail - an address under one of the tenant's accepted domains (subdomains too) other than the
                          mailbox's own: a named colleague is the impersonation target for BEC payment fraud
          ExternalEmail - any other address (a personal or partner address)
          Phone         - a North American or +international phone number (text, or a tel: link)
          Travel        - a small keyword list (travelling, vacation, holiday, abroad, overseas, out of the country,
                          conference, trade show, flight, business trip, in transit). City names are deliberately not
                          matched: too many false positives for too little gain.
          ReturnDate    - a written date (Nov 5, 11/05, 2026-11-05) or "back on Monday"
          Title         - a job title (CFO, controller, office manager, executive assistant...)
          Finance       - invoices, payments, wires, ACH, payroll, accounts payable, remittance, banking details...
        Snippet is the plain text with every email address and phone number replaced by [email] / [phone], cut to
        160 characters, so it can go into alert text without repeating contact details. Text is the full plain text
        for the report page only. Aspendora fork addition (Vikunja CIPP-40).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Message,
        [string[]]$AcceptedDomains = @(),
        [string[]]$OwnAddresses = @()
    )

    $Raw = [string]$Message
    # Strip HTML: drop script/style blocks, turn block ends into line breaks, remove the rest of the tags, decode entities.
    $Text = $Raw -replace '(?is)<(script|style)\b[^>]*>.*?</\1\s*>', ' '
    $Text = $Text -replace '(?i)<br\s*/?>|</(p|div|li|tr|h[1-6])\s*>', "`n"
    $Text = $Text -replace '(?s)<[^>]*>', ' '
    $Text = [System.Net.WebUtility]::HtmlDecode($Text)
    $Text = $Text -replace '[ \t\u00A0]+', ' '
    $Text = ($Text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join "`n"

    # mailto:/tel: links can carry an address the visible text does not show, so they are scanned too.
    $LinkTargets = @([regex]::Matches($Raw, '(?i)\b(?:mailto|tel):([^"''\s>?]+)') | ForEach-Object { [System.Net.WebUtility]::UrlDecode($_.Groups[1].Value) })
    $Haystack = (@($Text) + $LinkTargets) -join "`n"

    $EmailPattern = '[A-Za-z0-9._%+''-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
    # 10 digits with optional +1 / (area code) / separators, or a +country number of 8 to 15 digits.
    $PhonePattern = '(?<![\w+/])(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?![\w/])|(?<![\w+])\+\d(?:[\s.-]?\d){7,14}(?!\d)'

    $Accepted = @($AcceptedDomains | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
    $Own = @($OwnAddresses | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })

    $InternalEmails = [System.Collections.Generic.List[string]]::new()
    $ExternalEmails = [System.Collections.Generic.List[string]]::new()
    foreach ($Hit in [regex]::Matches($Haystack, $EmailPattern)) {
        $Address = $Hit.Value.Trim('.').ToLowerInvariant()
        if ($Address -in $Own) { continue }
        $Domain = ($Address -split '@')[-1]
        $IsInternal = $false
        foreach ($D in $Accepted) {
            if ($Domain -eq $D -or $Domain.EndsWith(".$D")) { $IsInternal = $true; break }
        }
        $Target = if ($IsInternal) { $InternalEmails } else { $ExternalEmails }
        if (-not $Target.Contains($Address)) { $Target.Add($Address) }
    }

    $Phones = [System.Collections.Generic.List[string]]::new()
    foreach ($Hit in [regex]::Matches($Haystack, $PhonePattern)) {
        $Digits = $Hit.Value -replace '\D', ''
        if (-not $Phones.Contains($Digits)) { $Phones.Add($Digits) }
    }

    $TravelPattern = '(?i)\b(?:travell?ing|travel|business trip|vacation|holiday|holidays|abroad|overseas|out of (?:the )?country|conference|trade ?show|flight|flying|in transit)\b'
    $Month = '(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)'
    $Weekday = '(?:mon|tues|wednes|thurs|fri|satur|sun)day'
    $DatePattern = "(?i)\b$Month\.?\s+\d{1,2}(?:st|nd|rd|th)?\b|\b\d{1,2}/\d{1,2}(?:/\d{2,4})?\b|\b\d{4}-\d{2}-\d{2}\b|\b(?:return(?:ing)?|back)\b[^.\n]{0,25}\b$Weekday\b"
    $TitlePattern = '(?i)\b(?:CEO|CFO|COO|CTO|controller|comptroller|treasurer|president|vice president|director|(?:office|general|accounting|finance|operations|project|practice|branch) manager|bookkeeper|accountant|(?:executive |administrative )?assistant)\b'
    # ACH is matched case-sensitively so a lower-case fragment cannot trip it; A/P and A/R need the slash.
    $FinancePattern = '(?i)\b(?:invoices?|invoicing|payments?|payables?|receivables?|payroll|billing|wires?|wire transfers?|remittances?|purchase orders?|banking|bank (?:details|account|info(?:rmation)?)|expense reports?|accounts? (?:payable|receivable))\b|\bA/[PR]\b|(?-i:\bACH\b)'

    $Travel = @([regex]::Matches($Text, $TravelPattern) | ForEach-Object { $_.Value.ToLowerInvariant() } | Select-Object -Unique)
    $Dates = @([regex]::Matches($Text, $DatePattern) | ForEach-Object { $_.Value } | Select-Object -Unique)
    $Titles = @([regex]::Matches($Text, $TitlePattern) | ForEach-Object { $_.Value.ToLowerInvariant() } | Select-Object -Unique)
    $Finance = @([regex]::Matches($Text, $FinancePattern) | ForEach-Object { $_.Value.ToLowerInvariant() } | Select-Object -Unique)

    $Flags = [System.Collections.Generic.List[string]]::new()
    if ($InternalEmails.Count -gt 0) { $Flags.Add('InternalEmail') }
    if ($ExternalEmails.Count -gt 0) { $Flags.Add('ExternalEmail') }
    if ($Phones.Count -gt 0) { $Flags.Add('Phone') }
    if ($Travel.Count -gt 0) { $Flags.Add('Travel') }
    if ($Dates.Count -gt 0) { $Flags.Add('ReturnDate') }
    if ($Titles.Count -gt 0) { $Flags.Add('Title') }
    if ($Finance.Count -gt 0) { $Flags.Add('Finance') }

    $Redacted = [regex]::Replace($Text, $EmailPattern, '[email]')
    $Redacted = [regex]::Replace($Redacted, $PhonePattern, '[phone]')
    $Redacted = ($Redacted -replace '\s+', ' ').Trim()
    $Snippet = if ($Redacted.Length -gt 160) { $Redacted.Substring(0, 157).TrimEnd() + '...' } else { $Redacted }

    [pscustomobject]@{
        Text           = $Text
        Snippet        = $Snippet
        Flags          = @($Flags)
        InternalEmails = @($InternalEmails)
        ExternalEmails = @($ExternalEmails)
        PhoneCount     = $Phones.Count
        TravelTerms    = $Travel
        Dates          = $Dates
        Titles         = $Titles
        FinanceTerms   = $Finance
    }
}
