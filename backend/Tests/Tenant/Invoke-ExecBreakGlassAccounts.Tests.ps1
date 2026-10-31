# Aspendora fork (Vikunja CIPP-3): break-glass account registry.

BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke($null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext { [int]$StatusCode; [object]$Body }

    function Get-CIPPTable { param($tablename) @{ TableName = $tablename } }
    function Get-CIPPAzDataTableEntity { param($TableName, $Filter) @($script:Store.Values | Where-Object { -not $Filter -or $Filter -match "PartitionKey eq '$($_.PartitionKey)'" }) }
    function Add-CIPPAzDataTableEntity { param($TableName, $Entity, [switch]$Force) $script:Store["$($Entity.PartitionKey)|$($Entity.RowKey)"] = [pscustomobject]$Entity }
    function Remove-AzDataTableEntity { param($TableName, $Entity, [switch]$Force) foreach ($E in $Entity) { $script:Store.Remove("$($E.PartitionKey)|$($E.RowKey)") } }
    function Get-Tenants { param($TenantFilter, [switch]$IncludeAll) [pscustomobject]@{ customerId = 'T1'; defaultDomainName = 'contoso.com' } }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$($Exception.Exception.Message)" } }
    function Get-CIPPCABreakGlassCandidate { param($Policies) [pscustomobject]@{ id = 'u-ca'; type = 'user'; count = 4 } }
    function New-GraphGetRequest {
        param($uri, $tenantid)
        if ($uri -match 'conditionalAccess') { return @(@{ id = 'p1' }) }
        if ($uri -match '/users/u-ca') { return [pscustomobject]@{ id = 'u-ca'; userPrincipalName = 'admin2@contoso.com'; displayName = 'Admin Two' } }
        if ($uri -match '/users/') { return [pscustomobject]@{ id = 'bg1'; userPrincipalName = 'bg@contoso.com'; displayName = 'Break Glass' } }
        if ($uri -match '/users\?') { return @([pscustomobject]@{ id = 'bg1'; userPrincipalName = 'bg@contoso.com'; displayName = 'Break Glass' }, [pscustomobject]@{ id = 'n1'; userPrincipalName = 'ann@contoso.com'; displayName = 'Ann' }) }
    }
    function Get-CIPPBreakGlassAccounts { param($TenantFilter) @($script:Store.Values) }
    . (Join-Path $BackendRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Identity/Administration/Users/Invoke-ExecBreakGlassAccounts.ps1')
    function Call { param($Body) Invoke-ExecBreakGlassAccounts -Request ([pscustomobject]@{ Headers = @{}; Query = @{}; Body = $Body }) }
}

Describe 'Invoke-ExecBreakGlassAccounts' {
    BeforeEach { $script:Store = @{} }

    It 'adds by UPN, keyed by tenant id and user object id, and lists it' {
        (Call @{ tenantFilter = 'contoso.com'; Action = 'Add'; UserPrincipalName = 'bg@contoso.com'; Note = 'vault' }).StatusCode | Should -Be 200
        $script:Store.Keys | Should -Be @('t1|bg1')
        $L = Call @{ tenantFilter = 'contoso.com' }
        $L.Body.Results.UserPrincipalName | Should -Be 'bg@contoso.com'
        $L.Body.Results.Tenant | Should -Be 'contoso.com'
    }

    It 'removes a registered account and 404s an unknown one' {
        $null = Call @{ tenantFilter = 'contoso.com'; Action = 'Add'; UserPrincipalName = 'bg@contoso.com' }
        (Call @{ tenantFilter = 'contoso.com'; Action = 'Remove'; UserPrincipalName = 'bg@contoso.com' }).StatusCode | Should -Be 200
        $script:Store.Count | Should -Be 0
        (Call @{ tenantFilter = 'contoso.com'; Action = 'Remove'; UserId = 'nope' }).StatusCode | Should -Be 404
    }

    It 'suggests the CA-exclusion candidate and break-glass-named accounts, flagging registered ones' {
        $null = Call @{ tenantFilter = 'contoso.com'; Action = 'Add'; UserId = 'bg1' }
        $S = (Call @{ tenantFilter = 'contoso.com'; Action = 'Suggest' }).Body.Results
        $S.UserPrincipalName | Should -Be @('admin2@contoso.com', 'bg@contoso.com')
        ($S | Where-Object UserId -EQ 'bg1').Registered | Should -BeTrue
        ($S | Where-Object UserId -EQ 'u-ca').Reason | Should -Match 'Conditional Access'
    }

    It 'requires a tenant and a user' {
        (Call @{ Action = 'Add' }).StatusCode | Should -Be 400
        (Call @{ tenantFilter = 'contoso.com'; Action = 'Add' }).StatusCode | Should -Be 400
    }
}
