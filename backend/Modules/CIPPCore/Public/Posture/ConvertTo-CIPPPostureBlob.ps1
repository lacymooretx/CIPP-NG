function ConvertTo-CIPPPostureBlob {
    <#
    .SYNOPSIS
        Pack posture snapshot test rows into gzip + base64 chunks that fit Azure Table string properties.
    .DESCRIPTION
        A tenant has ~600 CIPPTests results; even trimmed to id/name/suite/category/status/risk that is ~70 KB of
        JSON, over the 64 KiB per-property limit (and a string property holds only 32K characters, because the table
        service stores UTF-16). Gzip shrinks the repetitive rows roughly 5x, and the base64 text is then cut into
        30,000-character chunks so the entity stays valid even for a tenant with thousands of checks, without relying
        on the large-entity row splitting (which a projected -Property read cannot reassemble).

        Rows are arrays [Id, Name, Suite, Category, Status, Risk] wrapped in an object ({ v, t }) so a single row
        survives ConvertFrom-Json: a bare top-level array of one element is unrolled into its cells.
        Aspendora fork addition (Vikunja CIPP-16).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        $Tests,
        [int]$ChunkSize = 30000
    )

    $Rows = [System.Collections.Generic.List[object]]::new()
    foreach ($T in @($Tests)) {
        if ($null -eq $T) { continue }
        $Rows.Add(@([string]$T.Id, [string]$T.Name, [string]$T.Suite, [string]$T.Category, [string]$T.Status, [string]$T.Risk))
    }
    $Json = ConvertTo-Json -InputObject @{ v = 1; t = $Rows } -Depth 4 -Compress

    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
    $Buffer = [System.IO.MemoryStream]::new()
    try {
        $Gzip = [System.IO.Compression.GZipStream]::new($Buffer, [System.IO.Compression.CompressionLevel]::Optimal, $true)
        $Gzip.Write($Bytes, 0, $Bytes.Length)
        $Gzip.Dispose()
        $Text = [Convert]::ToBase64String($Buffer.ToArray())
    } finally {
        $Buffer.Dispose()
    }

    $Chunks = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Text.Length; $i += $ChunkSize) {
        $Chunks.Add($Text.Substring($i, [math]::Min($ChunkSize, $Text.Length - $i)))
    }
    return , $Chunks
}
