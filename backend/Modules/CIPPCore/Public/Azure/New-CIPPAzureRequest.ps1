function New-CIPPAzureRequest {
    <#
    .SYNOPSIS
        Call Azure Resource Manager in a client tenant as the CIPP-SAM service principal (app-only)
    .DESCRIPTION
        ARM access for client subscriptions is granted through Azure RBAC on the subscription (Reader),
        not through GDAP or API permissions, so the token is always app-only. A subscription the SAM
        principal has no role on is simply invisible, which is why an empty result is normal for a
        tenant nobody has onboarded.

        GET requests follow ARM's `nextLink` paging (Graph's `@odata.nextLink` paging in
        New-GraphGetRequest does not apply here). 429 and 5xx are retried, honouring Retry-After.
    .PARAMETER TenantFilter
        Tenant default domain or id.
    .PARAMETER Uri
        Absolute ARM URI, or a path starting with '/' (prefixed with https://management.azure.com).
    .PARAMETER Method
        GET (default) or POST.
    .PARAMETER Body
        Request body for POST; serialised to JSON.
    .PARAMETER NoPagination
        Return the first page only.
    .PARAMETER Raw
        Return the response object as-is instead of unwrapping `value`.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET',

        $Body,

        [switch]$NoPagination,

        [switch]$Raw,

        [int]$MaxRetries = 4
    )

    if ($Uri.StartsWith('/')) { $Uri = "https://management.azure.com$Uri" }

    $Headers = Get-GraphToken -tenantid $TenantFilter -scope 'https://management.azure.com/.default' -AsApp $true
    $JsonBody = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 20 -Compress } else { $null }

    $NextUri = $Uri
    do {
        $Attempt = 0
        while ($true) {
            $Attempt++
            $RequestParams = @{
                Uri                     = $NextUri
                Method                  = $Method
                Headers                 = $Headers
                ContentType             = 'application/json'
                SkipHttpErrorCheck      = $true
                StatusCodeVariable      = 'StatusCode'
                ResponseHeadersVariable = 'ResponseHeaders'
            }
            if ($JsonBody) { $RequestParams.Body = $JsonBody }
            $Response = Invoke-CIPPRestMethod @RequestParams

            if ($StatusCode -ge 200 -and $StatusCode -lt 300) { break }

            $Retryable = $StatusCode -eq 429 -or $StatusCode -ge 500
            if ($Retryable -and $Attempt -le $MaxRetries) {
                $RetryAfter = $ResponseHeaders.GetEnumerator() | Where-Object { $_.Key -eq 'Retry-After' } | Select-Object -First 1 -ExpandProperty Value
                if ($RetryAfter -is [array]) { $RetryAfter = $RetryAfter[0] }
                $Delay = if ($RetryAfter -as [int]) { [Math]::Min([int]$RetryAfter, 60) } else { [Math]::Pow(2, $Attempt) }
                Start-Sleep -Seconds $Delay
                continue
            }

            # Resource Graph puts the useful part (e.g. the KQL parse error) in error.details[].
            $ErrorText = if ($Response.error.message) {
                $Details = @($Response.error.details | ForEach-Object { if ($_.token) { "$($_.message) at position $($_.characterPositionInLine) near '$($_.token)'" } else { $_.message } } | Where-Object { $_ })
                "$($Response.error.code): $($Response.error.message)" + $(if ($Details) { ' ' + ($Details -join ' ') })
            } else { "$Response" }
            throw "Azure request failed ($StatusCode) for $($NextUri.Split('?')[0]): $ErrorText"
        }

        if ($Raw) { return $Response }

        if ($null -ne $Response.PSObject.Properties['value']) {
            $Response.value
        } else {
            $Response
            break
        }

        $NextUri = if ($NoPagination) { $null } else { $Response.nextLink }
    } while ($NextUri)
}
