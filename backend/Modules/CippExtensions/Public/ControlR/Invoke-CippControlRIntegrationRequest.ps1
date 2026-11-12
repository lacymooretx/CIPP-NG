function Invoke-CippControlRIntegrationRequest {
    <#
    .FUNCTIONALITY
        Internal
    .SYNOPSIS
        Calls ControlR's integration API with the CIPP integration token.
    .DESCRIPTION
        The token lives in the key vault as ControlRIntegration and is sent only in the x-personal-token header. It is
        never returned or logged. A refusal or failure comes back as Status plus a message, never as an empty success.
        Aspendora fork addition.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        $Body,
        # Break-glass rotate is synchronous (Hudu, Keeper, Graph, verify): ControlR asks for 90 s.
        [int]$TimeoutSec = 60
    )

    $Token = Get-ExtensionAPIKey -Extension 'ControlRIntegration'
    if ([string]::IsNullOrWhiteSpace($Token)) {
        return [pscustomobject]@{ Status = 500; Data = $null; Message = 'The ControlR integration token is not configured (key vault secret ControlRIntegration).' }
    }

    $Params = @{
        Uri                = "https://control.aspendora.com/api/integration/$($Path.TrimStart('/'))"
        Method             = $Method
        Headers            = @{ 'x-personal-token' = $Token }
        ContentType        = 'application/json'
        TimeoutSec         = $TimeoutSec
        SkipHttpErrorCheck = $true
        StatusCodeVariable = 'StatusCode'
    }
    if ($null -ne $Body) { $Params.Body = ($Body | ConvertTo-Json -Depth 8 -Compress) }

    try {
        $Response = Invoke-RestMethod @Params
    } catch {
        return [pscustomobject]@{ Status = 502; Data = $null; Message = "Could not reach ControlR: $($_.Exception.Message)" }
    }

    if ([int]$StatusCode -ge 200 -and [int]$StatusCode -lt 300) {
        return [pscustomobject]@{ Status = [int]$StatusCode; Data = $Response; Message = $null }
    }
    # ControlR answers errors as ProblemDetails; 'detail' is plain English and safe to show (never a secret).
    # 403s for role or allow-list problems come back as plain text, not JSON: show that text instead (truncated).
    $Detail = if ($Response -is [string]) { $Response.Trim() } else { try { [string]$Response.detail } catch { $null } }
    if ($Detail -and $Detail.Length -gt 400) { $Detail = $Detail.Substring(0, 400) + '…' }
    return [pscustomobject]@{ Status = [int]$StatusCode; Data = $null; Message = "ControlR returned HTTP $([int]$StatusCode)$(if ($Detail) { ": $Detail" } else { '.' })" }
}
