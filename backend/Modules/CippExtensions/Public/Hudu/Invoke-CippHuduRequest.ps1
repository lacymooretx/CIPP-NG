function Invoke-CippHuduRequest {
    <#
    .SYNOPSIS
    Minimal authenticated Hudu REST call used by the password-delivery path.

    .DESCRIPTION
    The HuduAPI module keeps its request function private and its Set-HuduPassword
    round-trips the whole record, which writes the record's own `url` (the Hudu page)
    back into the login-URL field. This wrapper sends exactly the body it is given.

    Terminating on failure, so callers wrap it in try/catch. A single retry after 30s
    on HTTP 429 (Hudu's limit is 300 requests per minute, shared across every client).

    Aspendora fork addition.

    .PARAMETER Configuration
    The parsed extension configuration (needs Hudu.BaseURL).

    .PARAMETER Method
    HTTP method.

    .PARAMETER Resource
    Path under /api/v1, e.g. '/asset_passwords'.

    .PARAMETER Params
    Query string values. Hudu silently ignores unknown parameters, so callers must
    still check results client-side.

    .PARAMETER Body
    Object serialised to JSON for POST/PUT.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Configuration,

        [string]$Method = 'GET',

        [Parameter(Mandatory)]
        [string]$Resource,

        [hashtable]$Params = @{},

        $Body
    )

    $BaseUrl = [string]$Configuration.Hudu.BaseURL
    if ([string]::IsNullOrWhiteSpace($BaseUrl)) { throw 'The Hudu base URL is not configured.' }
    $BaseUrl = $BaseUrl.TrimEnd('/')

    $APIKey = Get-ExtensionAPIKey -Extension 'Hudu'
    if ([string]::IsNullOrWhiteSpace($APIKey)) { throw 'No Hudu API key is stored for the Hudu extension.' }

    $Query = if ($Params.Count -gt 0) {
        '?' + (($Params.GetEnumerator() | Sort-Object Key | ForEach-Object {
                    '{0}={1}' -f [System.Uri]::EscapeDataString([string]$_.Key), [System.Uri]::EscapeDataString([string]$_.Value)
                }) -join '&')
    } else { '' }

    $Request = @{
        Method      = $Method
        Uri         = "$BaseUrl/api/v1$Resource$Query"
        Headers     = @{ 'x-api-key' = "$APIKey" }
        ContentType = 'application/json; charset=utf-8'
        ErrorAction = 'Stop'
    }
    if ($null -ne $Body) { $Request.Body = ($Body | ConvertTo-Json -Depth 10 -Compress) }

    try {
        Invoke-RestMethod @Request
    } catch {
        $Status = $_.Exception.Response.StatusCode.value__
        if ($Status -eq 429) {
            Start-Sleep -Seconds 30
            Invoke-RestMethod @Request
        } else {
            throw
        }
    }
}
