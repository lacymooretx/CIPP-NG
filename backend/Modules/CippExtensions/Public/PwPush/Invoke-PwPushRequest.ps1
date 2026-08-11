function Invoke-PwPushRequest {
    <#
    .SYNOPSIS
    Calls the Password Pusher REST API directly.

    .DESCRIPTION
    The PassPushPosh module used by New-PwPushLink has no support for the dispatch
    endpoints, so this is a thin authenticated wrapper over the raw API. It handles
    both supported auth methods (X-User-Email/X-User-Token, or Bearer) and the
    Cloudflare ZTNA service-token headers when the instance sits behind a tunnel.

    Aspendora fork addition.

    .PARAMETER Path
    Path relative to the instance base URL, e.g. '/p.json', or a full URL.

    .PARAMETER Method
    HTTP method. Defaults to GET.

    .PARAMETER Body
    Request body. Hashtables and objects are serialised to JSON; strings are sent as-is.

    .PARAMETER Configuration
    An already-loaded PwPush configuration. Fetched via Get-PwPushConfiguration when omitted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        $Body,

        $Configuration
    )

    if (-not $Configuration) { $Configuration = Get-PwPushConfiguration }
    if (-not $Configuration) { throw 'PwPush is not enabled or configured.' }

    $BaseUrl = if (![string]::IsNullOrWhiteSpace($Configuration.BaseUrl)) { $Configuration.BaseUrl.Trim().TrimEnd('/') } else { 'https://pwpush.com' }
    if ($BaseUrl -notmatch '^https?://') { $BaseUrl = "https://$BaseUrl" }

    $ApiKey = Get-ExtensionAPIKey -Extension 'PWPush'
    if ([string]::IsNullOrWhiteSpace($ApiKey)) { throw 'No PwPush API key is configured.' }

    $Headers = @{ 'Accept' = 'application/json' }
    if ($Configuration.UseBearerAuth -eq $true) {
        $Headers['Authorization'] = "Bearer $ApiKey"
    } else {
        if ([string]::IsNullOrWhiteSpace($Configuration.EmailAddress)) {
            throw 'PwPush is configured for email + token auth but no email address is set.'
        }
        $Headers['X-User-Email'] = $Configuration.EmailAddress
        $Headers['X-User-Token'] = $ApiKey
    }

    if ($Configuration.CFEnabled -eq $true -and $Configuration.FullConfiguration.CFZTNA.Enabled -eq $true) {
        $CFAPIKey = Get-ExtensionAPIKey -Extension 'CFZTNA'
        $Headers['CF-Access-Client-Id'] = $Configuration.FullConfiguration.CFZTNA.ClientId
        $Headers['CF-Access-Client-Secret'] = "$CFAPIKey"
    }

    $Uri = if ($Path -match '^https?://') { $Path } else { "$BaseUrl/$($Path.TrimStart('/'))" }

    $Splat = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $Headers
        ContentType = 'application/json'
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $Splat['Body'] = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 -Compress }
    }

    Invoke-RestMethod @Splat
}
