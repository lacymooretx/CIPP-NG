function Get-CIPPMessageTraceRange {
    <#
    .SYNOPSIS
        Reads Get-MessageTraceV2 over a date range, in 10-day windows and 5000-row pages, with a page cap.
    .DESCRIPTION
        Get-MessageTraceV2 keeps 90 days, answers at most 10 days and 5000 rows per query, has no paging
        token and does not accept wildcards. This walks the range newest-first: each window is queried, and
        while a page comes back full the next page reuses the last row's Received as EndDate and its
        RecipientAddress as StartingRecipientAddress (Microsoft's documented continuation). Rows are de-duplicated
        on MessageTraceId + RecipientAddress.

        Read-only: unlike ListMessageTrace it never provisions the Graph message trace service principal.
        MaxPages bounds the run (a busy tenant can produce ~5000 rows a day once journaling is counted); when it is
        hit, Truncated is true and OldestUtc says how far back the data actually reaches.
        Aspendora fork addition (Vikunja CIPP-30 / CIPP-38).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantFilter,
        [Parameter(Mandatory)][DateTime]$StartUtc,
        [Parameter(Mandatory)][DateTime]$EndUtc,
        [string[]]$SenderAddress,
        [string[]]$RecipientAddress,
        [ValidateRange(1, 5000)][int]$PageSize = 5000,
        [ValidateRange(1, 200)][int]$MaxPages = 20
    )

    $StartUtc = [DateTime]::SpecifyKind($StartUtc, [DateTimeKind]::Utc)
    $EndUtc = [DateTime]::SpecifyKind($EndUtc, [DateTimeKind]::Utc)
    $Floor = [DateTime]::UtcNow.AddDays(-90)
    if ($StartUtc -lt $Floor) { $StartUtc = $Floor }
    $Format = 'yyyy-MM-ddTHH:mm:ss.fffZ'

    $Seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Rows = [System.Collections.Generic.List[object]]::new()
    $Pages = 0
    $Truncated = $false
    $Oldest = $null

    $WindowEnd = $EndUtc
    while ($WindowEnd -gt $StartUtc -and -not $Truncated) {
        $WindowStart = $WindowEnd.AddDays(-10)
        if ($WindowStart -lt $StartUtc) { $WindowStart = $StartUtc }
        $CursorEnd = $WindowEnd
        $StartingRecipient = $null
        do {
            if ($Pages -ge $MaxPages) { $Truncated = $true; break }
            $CmdParams = @{ StartDate = $WindowStart.ToString($Format); EndDate = $CursorEnd.ToString($Format); ResultSize = $PageSize }
            if ($SenderAddress) { $CmdParams.SenderAddress = @($SenderAddress) }
            if ($RecipientAddress) { $CmdParams.RecipientAddress = @($RecipientAddress) }
            if ($StartingRecipient) { $CmdParams.StartingRecipientAddress = $StartingRecipient }
            $Page = @(New-ExoRequest -tenantid $TenantFilter -cmdlet 'Get-MessageTraceV2' -cmdParams $CmdParams)
            $Pages++
            foreach ($Row in $Page) {
                if ($null -eq $Row) { continue }
                if ($Seen.Add("$($Row.MessageTraceId)|$($Row.RecipientAddress)")) { $Rows.Add($Row) }
            }
            $Full = $Page.Count -ge $PageSize
            if ($Page.Count -gt 0) {
                $Last = $Page[-1]
                $LastTime = ConvertTo-CIPPCentralTime -Value $Last.Received
                if ($LastTime) {
                    $LastUtc = [DateTime]::Parse($LastTime.Utc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                    if (-not $Oldest -or $LastUtc -lt $Oldest) { $Oldest = $LastUtc }
                    $CursorEnd = $LastUtc
                }
                $StartingRecipient = [string]$Last.RecipientAddress
            }
        } while ($Full)
        if (-not $Truncated) {
            $Oldest = $WindowStart
            $WindowEnd = $WindowStart
        }
    }

    [pscustomobject]@{
        Rows      = $Rows
        Pages     = $Pages
        Truncated = $Truncated
        StartUtc  = $StartUtc
        EndUtc    = $EndUtc
        OldestUtc = $Oldest
    }
}
