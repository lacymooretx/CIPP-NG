function ConvertFrom-CIPPPostureBlob {
    <#
    .SYNOPSIS
        Unpack the gzip + base64 chunks written by ConvertTo-CIPPPostureBlob back into test objects.
    .DESCRIPTION
        Takes the chunk strings in order (Data0, Data1, ...) and returns a list of
        [pscustomobject]@{ Id; Name; Suite; Category; Status; Risk }. Aspendora fork addition (Vikunja CIPP-16).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Chunks
    )

    $Tests = [System.Collections.Generic.List[object]]::new()
    $Text = (@($Chunks) | Where-Object { $_ }) -join ''
    if (-not $Text) { return , $Tests }

    $Source = [System.IO.MemoryStream]::new([Convert]::FromBase64String($Text))
    try {
        $Gzip = [System.IO.Compression.GZipStream]::new($Source, [System.IO.Compression.CompressionMode]::Decompress)
        $Reader = [System.IO.StreamReader]::new($Gzip, [System.Text.Encoding]::UTF8)
        $Json = $Reader.ReadToEnd()
        $Reader.Dispose()
    } finally {
        $Source.Dispose()
    }

    $Parsed = ConvertFrom-Json -InputObject $Json
    $Rows = @($Parsed.t)
    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $R = @($Rows[$i])
        $Tests.Add([pscustomobject]@{
                Id       = [string]$R[0]
                Name     = [string]$R[1]
                Suite    = [string]$R[2]
                Category = [string]$R[3]
                Status   = [string]$R[4]
                Risk     = [string]$R[5]
            })
    }
    return , $Tests
}
