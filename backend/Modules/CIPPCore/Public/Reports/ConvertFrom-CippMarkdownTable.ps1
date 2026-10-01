function ConvertFrom-CippMarkdownTable {
    <#
    .SYNOPSIS
        Parse the first Markdown table in a test result into column names and row cell arrays
    .DESCRIPTION
        Test results store their findings as Markdown (see Format-CippAzureFindingTable). Reports
        need the same rows as data. Escaped pipes (\|) inside cells are preserved. Returns
        @{ Columns = string[]; Rows = List[object] (each a string[]) }, or $null when there is no table.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param([string]$Markdown)

    if ([string]::IsNullOrWhiteSpace($Markdown)) { return $null }
    $Lines = @($Markdown -split "`r?`n" | Where-Object { $_.TrimStart().StartsWith('|') })
    if ($Lines.Count -lt 2) { return $null }

    # Cells are written by ConvertTo-CippMarkdownCell: '\' escapes the next character ('\\' or '\|').
    $Split = {
        param($Line)
        $Inner = $Line.Trim()
        $Cells = [System.Collections.Generic.List[string]]::new()
        $Cell = [System.Text.StringBuilder]::new()
        for ($i = 1; $i -lt $Inner.Length; $i++) {
            $Ch = $Inner[$i]
            if ($Ch -eq '\' -and $i + 1 -lt $Inner.Length) { [void]$Cell.Append($Inner[++$i]); continue }
            if ($Ch -eq '|') { $Cells.Add($Cell.ToString().Trim()); [void]$Cell.Clear(); continue }
            [void]$Cell.Append($Ch)
        }
        , [string[]]$Cells
    }

    $Columns = & $Split $Lines[0]
    $Rows = [System.Collections.Generic.List[object]]::new()
    foreach ($Line in ($Lines | Select-Object -Skip 1)) {
        if ($Line -match '^\s*\|(\s*:?-{3,}:?\s*\|)+\s*$') { continue }
        $Rows.Add([string[]](& $Split $Line))
    }
    @{ Columns = $Columns; Rows = $Rows }
}
