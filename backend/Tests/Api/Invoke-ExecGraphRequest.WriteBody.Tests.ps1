# A write through the Graph passthrough with no body must be refused before it reaches Graph.
# Graph answers a bodyless PATCH/POST/PUT 2xx with no content, which is byte-identical to an
# applied write, so without this guard the caller is told a change succeeded that was never even
# described. DELETE legitimately carries no body and must still pass through.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/CIPP/Core/Invoke-ExecGraphRequest.ps1'

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }

    function New-GraphGetRequest { param($uri, $tenantid, $noPagination, $AsApp) $script:LastGet = @{ Uri = $uri }; return @{ ok = $true } }
    function New-GraphPOSTRequest { param($uri, $tenantid, $type, $body, $AsApp) $script:LastPost = @{ Uri = $uri; Type = $type; Body = $body }; return $null }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) $script:Logs += $message }
    function Get-NormalizedError { param($Message) $Message }

    . $FunctionPath

    function New-TestRequest {
        param($Method, $GraphBody, $Endpoint = 'policies/authorizationPolicy')
        $BodyObj = @{ TenantFilter = 'contoso.com'; Endpoint = $Endpoint; Method = $Method }
        if ($PSBoundParameters.ContainsKey('GraphBody')) { $BodyObj.GraphRequestBody = $GraphBody }
        [pscustomobject]@{
            Params  = @{ CIPPEndpoint = 'ExecGraphRequest' }
            Headers = @{}
            Query   = [pscustomobject]@{}
            Body    = [pscustomobject]$BodyObj
        }
    }
}

Describe 'Invoke-ExecGraphRequest write body guard' {
    BeforeEach {
        $script:LastPost = $null
        $script:LastGet = $null
        $script:Logs = @()
    }

    It 'refuses <_> with no body and never calls Graph' -ForEach @('POST', 'PATCH', 'PUT') {
        $Response = Invoke-ExecGraphRequest -Request (New-TestRequest -Method $_)

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Be "Method $_ requires a Body/GraphRequestBody."
        $script:LastPost | Should -BeNullOrEmpty
    }

    It 'refuses a write whose body is an empty string' {
        $Response = Invoke-ExecGraphRequest -Request (New-TestRequest -Method 'PATCH' -GraphBody '')

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $script:LastPost | Should -BeNullOrEmpty
    }

    It 'allows a write that carries a body, and forwards it verbatim' {
        $Body = '{"description":"x"}'
        $Response = Invoke-ExecGraphRequest -Request (New-TestRequest -Method 'PATCH' -GraphBody $Body)

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:LastPost.Body | Should -Be $Body
        $script:LastPost.Type | Should -Be 'PATCH'
    }

    It 'records the outgoing body length in the audit line, not the body' {
        $Body = '{"description":"secret-value"}'
        $null = Invoke-ExecGraphRequest -Request (New-TestRequest -Method 'PATCH' -GraphBody $Body)

        $Audit = $script:Logs | Where-Object { $_ -match '^Executed Graph' }
        $Audit | Should -Match "request body: $($Body.Length) chars"
        $Audit | Should -Not -Match 'secret-value'
    }

    It 'still allows DELETE with no body' {
        $Response = Invoke-ExecGraphRequest -Request (New-TestRequest -Method 'DELETE')

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:LastPost.Type | Should -Be 'DELETE'
    }

    It 'still allows GET with no body' {
        $Response = Invoke-ExecGraphRequest -Request (New-TestRequest -Method 'GET')

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:LastGet | Should -Not -BeNullOrEmpty
    }
}
