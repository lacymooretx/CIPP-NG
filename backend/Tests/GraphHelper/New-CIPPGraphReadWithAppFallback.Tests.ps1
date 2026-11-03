# Aspendora fork: delegated read with an app-only retry when the token's user lacks the rights (partner tenant).
BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/GraphHelper/New-CIPPGraphReadWithAppFallback.ps1')
    function New-GraphGetRequest {
        [CmdletBinding()]
        param($uri, $tenantid, $noPagination, $AsApp)
        $script:Calls += , [bool]$AsApp
        $Answer = if ($AsApp) { $script:App } else { $script:Delegated }
        if ($Answer -is [string] -and $Answer -like 'THROW:*') { throw $Answer.Substring(6) }
        return $Answer
    }
    function Invoke-Read { New-CIPPGraphReadWithAppFallback -uri 'https://graph.microsoft.com/x' -tenantid 'contoso.com' }
}

Describe 'New-CIPPGraphReadWithAppFallback' {
    BeforeEach { $script:Calls = @(); $script:Delegated = @('d'); $script:App = @('a') }

    It 'stays delegated when the read works, as in client tenants' {
        Invoke-Read | Should -Be 'd'
        $script:Calls | Should -Be @($false)
    }

    It 'retries as the app on <Message>' -ForEach @(
        @{ Message = 'You cannot perform the requested operation, Signed in user is missing required roles.' }
        @{ Message = 'User is not in the allowed roles' }
        @{ Message = 'Forbidden' }
        @{ Message = '{"HttpHeaders":"{\"WWW-Authenticate\":\"Bearer\"}"}' }
    ) {
        $script:Delegated = "THROW:$Message"
        Invoke-Read | Should -Be 'a'
        $script:Calls | Should -Be @($false, $true)
    }

    It 'does not retry a licence error or a throttle' -ForEach @(
        @{ Message = 'Authentication_RequestFromNonPremiumTenantOrB2CTenant' }
        @{ Message = 'Forbidden: tenant has no premium license' }
        @{ Message = 'TooManyRequests' }
    ) {
        $script:Delegated = "THROW:$Message"
        { Invoke-Read } | Should -Throw "*$Message*"
        $script:Calls.Count | Should -Be 1
    }

    It 'throws both errors when the retry fails too' {
        $script:Delegated = 'THROW:missing required roles'
        $script:App = 'THROW:required scopes are missing in the token'
        { Invoke-Read } | Should -Throw '*missing required roles*retry as the app*required scopes*'
    }

    It 'returns an empty app-only result without treating it as a failure' {
        $script:Delegated = 'THROW:missing required roles'
        $script:App = @()
        @(Invoke-Read).Count | Should -Be 0
        $script:Calls.Count | Should -Be 2
    }
}
