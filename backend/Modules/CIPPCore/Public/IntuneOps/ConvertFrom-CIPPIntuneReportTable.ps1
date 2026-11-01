function ConvertFrom-CIPPIntuneReportTable {
    <#
    .SYNOPSIS
        Turns an Intune reports-API response (Schema + Values) into one object per row.
    .DESCRIPTION
        Pure function. deviceManagement/reports/* answer with a column list (Schema[].Column) and rows as positional
        arrays (Values[][]). Rows are walked by index, never with foreach over @($Report.Values): wrapping an array of
        arrays in @() flattens a single-row result into its cells, and every field then comes out empty (the trap
        documented in Invoke-ListIntuneDeploymentStatus).
        Aspendora fork addition (Vikunja CIPP-27).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param($Report)
    if ($null -eq $Report -or $null -eq $Report.Values) { return @() }
    $Columns = @($Report.Schema | ForEach-Object { [string]$_.Column })
    $Values = $Report.Values
    # A single row can arrive already unwrapped (an array of scalars); treat that as one row.
    $SingleRow = $Values.Count -gt 0 -and -not ($Values[0] -is [System.Collections.IList])
    $RowCount = if ($SingleRow) { 1 } else { $Values.Count }
    $Out = [System.Collections.Generic.List[object]]::new()
    for ($r = 0; $r -lt $RowCount; $r++) {
        $Cells = if ($SingleRow) { $Values } else { $Values[$r] }
        $Item = [ordered]@{}
        for ($i = 0; $i -lt $Columns.Count -and $i -lt $Cells.Count; $i++) { $Item[$Columns[$i]] = $Cells[$i] }
        $Out.Add([pscustomobject]$Item)
    }
    # Unrolled on purpose: callers wrap the call in @().
    return $Out.ToArray()
}
