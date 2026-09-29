# ExecGraphRequest GET semantics (gaps doc §13, 2026-09-28).
# A. `$top=5` against a 24k-item Inbox crawled every page and timed out at the gateway, because
#    New-GraphGetRequest follows @odata.nextLink unless told not to. `$top` now means one page.
# B. An empty collection and a failed read both came back as {"Results":null} with HTTP 200,
#    so "no sign-ins" was indistinguishable from "couldn't read sign-ins" during a compromise check.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/CIPP/Core/Invoke-ExecGraphRequest.ps1'

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }

    # Fake Graph: $script:Pages is a list of raw responses served in order; each call is recorded.
    function New-GraphGetRequest {
        param($uri, $tenantid, $AsApp, [switch]$ReturnRawResponse)
        $script:Calls.Add(@{ Uri = $uri; AsApp = $AsApp; Raw = [bool]$ReturnRawResponse })
        if ($script:Pages.Count -eq 0) { return $null }
        $Next = $script:Pages[0]
        $script:Pages.RemoveAt(0)
        return $Next
    }
    function New-GraphPOSTRequest { throw 'not expected' }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) $script:Logs.Add($message) }
    function Get-NormalizedError { param($Message) $Message }
    function Start-Sleep { param($Seconds) $script:Slept += $Seconds }

    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Tools/ConvertTo-CIPPBoolean.ps1')
    . $FunctionPath

    function New-Page {
        param([int]$Count, [string]$Next, [int]$Start = 0)
        $Value = @(for ($i = 0; $i -lt $Count; $i++) { [pscustomobject]@{ id = "item$($Start + $i)" } })
        $Content = [pscustomobject]@{ value = $Value }
        if ($Next) { $Content | Add-Member -NotePropertyName '@odata.nextLink' -NotePropertyValue $Next }
        [pscustomobject]@{ StatusCode = 200; Content = $Content; Headers = @{} }
    }
    function Invoke-Get {
        param([string]$Endpoint, [hashtable]$Extra = @{})
        $Body = @{ TenantFilter = 'contoso.com'; Endpoint = $Endpoint } + $Extra
        Invoke-ExecGraphRequest -Request ([pscustomobject]@{
                Params  = @{ CIPPEndpoint = 'ExecGraphRequest' }
                Headers = @{}
                Query   = [pscustomobject]@{}
                Body    = [pscustomobject]$Body
            })
    }
}

Describe 'Invoke-ExecGraphRequest GET paging' {
    BeforeEach {
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        $script:Logs = [System.Collections.Generic.List[string]]::new()
        $script:Pages = [System.Collections.Generic.List[object]]::new()
        $script:Slept = 0
    }

    It 'returns ONE page when the endpoint carries $top and the caller did not set NoPagination' {
        $script:Pages.Add((New-Page -Count 5 -Next 'https://graph.microsoft.com/beta/next1'))
        $script:Pages.Add((New-Page -Count 5 -Start 5))

        $R = Invoke-Get -Endpoint 'users/a@contoso.com/mailFolders/Inbox/messages?$top=5&$orderby=receivedDateTime desc'

        $R.StatusCode | Should -Be 200
        $script:Calls.Count | Should -Be 1
        @($R.Body.Results).Count | Should -Be 5
        $R.Body.Metadata.NextLink | Should -Be 'https://graph.microsoft.com/beta/next1'
        $R.Body.Metadata.Truncated | Should -BeTrue
        $R.Body.Metadata.PaginationDefaulted | Should -BeTrue
    }

    It 'recognises a URL-encoded %24top too' {
        $script:Pages.Add((New-Page -Count 2 -Next 'https://graph.microsoft.com/beta/next1'))
        $script:Pages.Add((New-Page -Count 2))
        $null = Invoke-Get -Endpoint 'users?%24top=2'
        $script:Calls.Count | Should -Be 1
    }

    It 'follows nextLink when $top is present but the caller explicitly set NoPagination=<_>' -ForEach @('false', $false) {
        $script:Pages.Add((New-Page -Count 2 -Next 'https://graph.microsoft.com/beta/next1'))
        $script:Pages.Add((New-Page -Count 2 -Start 2))

        $R = Invoke-Get -Endpoint 'users?$top=2' -Extra @{ NoPagination = $_ }

        $script:Calls.Count | Should -Be 2
        @($R.Body.Results).Count | Should -Be 4
        $R.Body.Metadata.Truncated | Should -BeFalse
        $R.Body.Metadata.PaginationDefaulted | Should -BeFalse
    }

    It 'follows nextLink by default when there is no $top (existing callers keep full results)' {
        $script:Pages.Add((New-Page -Count 3 -Next 'https://graph.microsoft.com/beta/next1'))
        $script:Pages.Add((New-Page -Count 3 -Start 3 -Next 'https://graph.microsoft.com/beta/next2'))
        $script:Pages.Add((New-Page -Count 1 -Start 6))

        $R = Invoke-Get -Endpoint 'users'

        $script:Calls.Count | Should -Be 3
        $script:Calls[1].Uri | Should -Be 'https://graph.microsoft.com/beta/next1'
        @($R.Body.Results).id | Should -Be @('item0', 'item1', 'item2', 'item3', 'item4', 'item5', 'item6')
        $R.Body.Metadata.Pages | Should -Be 3
        $R.Body.Metadata.NextLink | Should -BeNullOrEmpty
    }

    It 'honours DisablePagination=true with no $top' {
        $script:Pages.Add((New-Page -Count 3 -Next 'https://graph.microsoft.com/beta/next1'))
        $R = Invoke-Get -Endpoint 'users' -Extra @{ DisablePagination = 'true' }
        $script:Calls.Count | Should -Be 1
        $R.Body.Metadata.Truncated | Should -BeTrue
    }

    It 'stops an unbounded crawl at MaxItems and hands back the NextLink' {
        for ($p = 0; $p -lt 10; $p++) { $script:Pages.Add((New-Page -Count 100 -Start ($p * 100) -Next "https://graph.microsoft.com/beta/p$($p + 1)")) }

        $R = Invoke-Get -Endpoint 'users' -Extra @{ MaxItems = '250' }

        $script:Calls.Count | Should -Be 3
        @($R.Body.Results).Count | Should -Be 300
        $R.Body.Metadata.Truncated | Should -BeTrue
        $R.Body.Metadata.NextLink | Should -Be 'https://graph.microsoft.com/beta/p3'
        ($script:Logs -join "`n") | Should -Match 'stopped paging'
    }

    It 'returns an EMPTY ARRAY, not null, for an empty collection' {
        $script:Pages.Add((New-Page -Count 0))

        $R = Invoke-Get -Endpoint "auditLogs/signIns?`$filter=userPrincipalName eq 'x@contoso.com'" -Extra @{ AsApp = 'true' }

        $R.StatusCode | Should -Be 200
        $R.Body.Metadata.Count | Should -Be 0
        $Json = $R.Body | ConvertTo-Json -Depth 5 -Compress
        $Json | Should -Match '"Results":\[\]'
        $script:Calls[0].AsApp | Should -BeTrue
    }

    It 'returns a single entity as-is, without Metadata' {
        $script:Pages.Add([pscustomobject]@{ StatusCode = 200; Content = [pscustomobject]@{ id = 'u1'; displayName = 'User' }; Headers = @{} })
        $R = Invoke-Get -Endpoint 'users/u1'
        $R.Body.Results.id | Should -Be 'u1'
        $R.Body.PSObject.Properties.Name | Should -Not -Contain 'Metadata'
    }

    It 'surfaces a Graph <_> with its own status code and message, never 200/null' -ForEach @(403, 404) {
        $Code = $_
        $script:Pages.Add([pscustomobject]@{
                StatusCode = $Code
                Content    = [pscustomobject]@{ error = [pscustomobject]@{ code = 'Authorization_RequestDenied'; message = 'Insufficient privileges to complete the operation.' } }
                Headers    = @{}
            })

        $R = Invoke-Get -Endpoint 'auditLogs/signIns' -Extra @{ AsApp = 'true' }

        $R.StatusCode | Should -Be $Code
        $R.Body.Results | Should -Match 'Insufficient privileges'
        $R.Body.Results | Should -Match "HTTP $Code"
    }

    It 'fails a page error mid-crawl instead of returning the partial set as success' {
        $script:Pages.Add((New-Page -Count 2 -Next 'https://graph.microsoft.com/beta/next1'))
        $script:Pages.Add([pscustomobject]@{ StatusCode = 500; Content = [pscustomobject]@{ error = [pscustomobject]@{ code = 'x'; message = 'boom' } }; Headers = @{} })
        $R = Invoke-Get -Endpoint 'users'
        $R.StatusCode | Should -Be 500
    }

    It 'returns 403, not null, when the tenant is not authorised (helper returns nothing)' {
        $R = Invoke-Get -Endpoint 'users'
        $R.StatusCode | Should -Be 403
        $R.Body.Results | Should -Match 'not authorised'
    }

    It 'retries a 429 honouring Retry-After, then succeeds' {
        $script:Pages.Add([pscustomobject]@{ StatusCode = 429; Content = $null; Headers = @{ 'Retry-After' = @('3') } })
        $script:Pages.Add((New-Page -Count 1))
        $R = Invoke-Get -Endpoint 'users'
        $R.StatusCode | Should -Be 200
        $script:Slept | Should -Be 3
    }
}
