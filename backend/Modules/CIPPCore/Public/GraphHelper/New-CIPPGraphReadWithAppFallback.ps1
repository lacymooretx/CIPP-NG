function New-CIPPGraphReadWithAppFallback {
    <#
    .SYNOPSIS
        Graph GET that uses CIPP's delegated token, and retries as the app only if the token's user lacks the rights.
    .DESCRIPTION
        In the partner tenant the delegated token's user holds no directory roles on purpose, so reads that need one are
        refused there. Client tenants answer through GDAP and never reach the retry, so nothing changes for them.
        Only a refusal retries: a licence error or throttling would fail the same way, and callers match on those
        messages. If the retry fails too, both errors are thrown, with the delegated one first so those matches still work.
        Read only. Aspendora fork addition (2026-11-02).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$uri,
        [Parameter(Mandatory)][string]$tenantid,
        $noPagination = $false
    )
    $Refused = 'missing required roles|not in the allowed roles|Forbidden|Authorization_RequestDenied|Insufficient privileges|\b403\b|WWW-Authenticate'
    $Licence = 'premium|licen[cs]e|Authentication_RequestFromNonPremiumTenantOrB2CTenant'
    try {
        return New-GraphGetRequest -uri $uri -tenantid $tenantid -noPagination $noPagination -ErrorAction Stop
    } catch {
        $Delegated = $_.Exception.Message
        if ($Delegated -notmatch $Refused -or $Delegated -match $Licence) { throw }
    }
    try {
        return New-GraphGetRequest -uri $uri -tenantid $tenantid -noPagination $noPagination -AsApp $true -ErrorAction Stop
    } catch {
        throw "$Delegated (retry as the app: $($_.Exception.Message))"
    }
}
