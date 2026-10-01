function Format-CippAzureFindingTable {
    <#
    .SYNOPSIS
        Markdown table of AZ_ test findings, capped so a large estate doesn't produce a huge result
    .PARAMETER Rows
        Ordered hashtables or objects; the first row's keys become the columns.
    .PARAMETER Max
        Rows shown before a "…and N more" line. Default 50.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [object[]]$Rows,
        [int]$Max = 50
    )
    $Rows = @($Rows | Where-Object { $null -ne $_ })
    if ($Rows.Count -eq 0) { return '' }

    $Columns = if ($Rows[0] -is [System.Collections.IDictionary]) { @($Rows[0].Keys) } else { @($Rows[0].PSObject.Properties.Name) }
    $Lines = [System.Collections.Generic.List[string]]::new()
    $Lines.Add('| ' + ($Columns -join ' | ') + ' |')
    $Lines.Add('|' + (@($Columns | ForEach-Object { ' --- ' }) -join '|') + '|')
    foreach ($Row in ($Rows | Select-Object -First $Max)) {
        $Cells = foreach ($C in $Columns) { ConvertTo-CippMarkdownCell -Value $Row.$C }
        $Lines.Add('| ' + ($Cells -join ' | ') + ' |')
    }
    if ($Rows.Count -gt $Max) { $Lines.Add(''); $Lines.Add("…and $($Rows.Count - $Max) more.") }
    $Lines -join "`n"
}
