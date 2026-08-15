function ConvertTo-ITGlueSectionHtml {
    <#
    .SYNOPSIS
        Render one report section as an HTML table that fits an IT Glue Textbox field.
    .DESCRIPTION
        IT Glue caps a flexible-asset Textbox trait at 64 kilobytes and rejects the whole
        write with HTTP 422 if any single trait exceeds it. Verified live: 43KB accepted,
        108KB rejected, message "is too long, must not exceed 64 kilobytes".

        A real tenant breaches this easily - 3E NDT's settings arrays alone are 105KB of
        raw JSON - so this renders defensively rather than optimistically. Rows are
        emitted until the budget is nearly spent, then the table is closed and a visible
        notice states exactly how many rows were withheld and where to find them.

        The rule that matters: truncation is always visible. A table that silently drops
        rows is worse than no documentation, because it reads as complete.
    .PARAMETER Section
        A report-model section: @{ Title; Description; Columns; Rows; Empty }.
    .PARAMETER MaxBytes
        Byte budget for the rendered HTML. Defaults to 60000, leaving headroom under the
        64KB (65536) hard limit for the truncation notice and any encoding growth.
    .PARAMETER Truncated
        Reference to a list. When truncation happens, a note describing it is added so the
        caller can surface it in the asset's Collection Notes field.
    .PARAMETER Overflow
        Reference to a list that receives parts 2..N when MaxParts is greater than 1.
        Aspendora's own tenant has 802 settings-catalog rows - 54% of them do not fit a
        single 64KB field - so the big sections are spread over continuation fields rather
        than truncated. Truncation is the last resort, not the first.
    .PARAMETER MaxParts
        Number of fields available for this section, including the first. Rows that still
        do not fit after the last part are truncated, visibly.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Section,

        [int]$MaxBytes = 60000,

        [System.Collections.Generic.List[object]]$Truncated,

        # Receives parts 2..N when a section needs more than one IT Glue field. The caller
        # maps them onto continuation traits ("Settings Catalog (continued)"). Part 1 is
        # always the return value, so single-field callers need not pass this.
        [System.Collections.Generic.List[string]]$Overflow,

        # How many fields the caller has available for this section, including the first.
        [int]$MaxParts = 1
    )

    function _enc([string]$v) {
        if ([string]::IsNullOrEmpty($v)) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($v)
    }
    function _cell($v) {
        if ($null -eq $v) { return '' }
        if ($v -is [bool]) { return $(if ($v) { 'Yes' } else { 'No' }) }
        if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
            return _enc ((@($v) | Select-Object -First 8) -join ', ')
        }
        return _enc ([string]$v)
    }

    $Title = [string]$Section.Title
    $Rows = @($Section.Rows)

    # Empty section: say so explicitly. "No policies" is documentation too.
    if ($Rows.Count -eq 0) {
        $EmptyText = if ($Section.Empty) { [string]$Section.Empty } else { 'Nothing configured.' }
        return "<p><em>$(_enc $EmptyText)</em></p>"
    }

    $Head = [System.Text.StringBuilder]::new()
    if ($Section.Description) {
        $null = $Head.Append("<p style=""margin:0 0 8px 0;color:#555;"">$(_enc ([string]$Section.Description))</p>")
    }
    # Styling lives on the table element only. Per-cell inline style was costing ~340 of
    # every 527 bytes per row, which on a real tenant is the difference between a complete
    # section and a half-truncated one.
    $null = $Head.Append('<table style="width:100%;border-collapse:collapse;font-size:12px;" border="1" cellpadding="3"><thead><tr>')
    foreach ($c in @($Section.Columns)) {
        $null = $Head.Append("<th style=""text-align:left;padding:4px 6px;background:#f5f5f5;border-bottom:1px solid #ddd;"">$(_enc ([string]$c))</th>")
    }
    $null = $Head.Append('</tr></thead><tbody>')

    $HeadHtml = $Head.ToString()
    $Tail = '</tbody></table>'

    # Reserve room for the closing tags and a worst-case truncation notice.
    $NoticeReserve = 320
    $Budget = $MaxBytes - $HeadHtml.Length - $Tail.Length - $NoticeReserve

    $Parts = [System.Collections.Generic.List[string]]::new()
    $Body = [System.Text.StringBuilder]::new()
    $Written = 0
    $PrevCells = $null
    $Index = 0

    while ($Index -lt $Rows.Count -and $Parts.Count -lt $MaxParts) {
        $Cells = @($Rows[$Index])
        $RowSb = [System.Text.StringBuilder]::new()
        $null = $RowSb.Append('<tr>')

        # Collapse repeated leading columns. A settings-catalog section repeats the policy
        # name and its assignment on every one of its settings; blanking the repeats reads
        # like a grouped table and buys back a large share of the byte budget.
        # $PrevCells is reset at every part boundary, so a continuation field never opens
        # with blank cells whose meaning lived in the previous field.
        $StillRepeating = $null -ne $PrevCells
        for ($i = 0; $i -lt $Cells.Count; $i++) {
            $Text = _cell $Cells[$i]
            if ($StillRepeating -and $i -lt $PrevCells.Count -and $Text -eq $PrevCells[$i] -and $Text -ne '') {
                $null = $RowSb.Append('<td></td>')
            } else {
                $StillRepeating = $false
                $null = $RowSb.Append("<td>$Text</td>")
            }
        }
        $null = $RowSb.Append('</tr>')
        $RowHtml = $RowSb.ToString()

        if (($Body.Length + $RowHtml.Length) -gt $Budget) {
            # This part is full. Close it and start the next one, unless a single row is
            # itself too large to ever fit - in which case advancing avoids an infinite loop.
            if ($Body.Length -eq 0) { $Index++; continue }
            $Parts.Add($HeadHtml + $Body.ToString() + $Tail)
            $Body = [System.Text.StringBuilder]::new()
            $PrevCells = $null
            continue
        }

        $null = $Body.Append($RowHtml)
        $PrevCells = @($Cells | ForEach-Object { _cell $_ })
        $Written++
        $Index++
    }

    if ($Body.Length -gt 0 -or $Parts.Count -eq 0) {
        $Parts.Add($HeadHtml + $Body.ToString() + $Tail)
    }

    if ($Written -lt $Rows.Count) {
        $Withheld = $Rows.Count - $Written
        $Where = if ($MaxParts -gt 1) { "the $MaxParts fields available for this section" } else { "IT Glue's 64KB field limit" }
        $Notice = "<p style=""margin:8px 0 0 0;padding:6px 8px;background:#fff4e5;border-left:3px solid #d97706;font-size:12px;"">" +
        "<strong>Truncated:</strong> showing $Written of $($Rows.Count) rows. " +
        "$Withheld more could not fit $Where - open the full report in CIPP for the complete list.</p>"
        $Parts[$Parts.Count - 1] += $Notice
        # $null -ne, not a truthiness test: an empty List[object] is falsy in PowerShell,
        # which would skip the note on exactly the first (and usually only) truncation.
        if ($null -ne $Truncated) {
            $Truncated.Add(@{
                    Section = $Title
                    Detail  = "Showed $Written of $($Rows.Count) rows; $Withheld withheld to stay under $Where."
                })
        }
    }

    if ($null -ne $Overflow) {
        for ($i = 1; $i -lt $Parts.Count; $i++) { $Overflow.Add($Parts[$i]) }
    }

    return $Parts[0]
}
