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

Describe 'Invoke-ExecGraphRequest verb-parameter guard' {
    # Reported from another session 2026-09-21 as "the ExecGraphRequest POST bug is still live":
    # a POST to an /assign endpoint came back "No OData route exists ... with http verb GET".
    # It was not a CIPP bug - the caller sent `Type: POST`, which this endpoint never read, so the
    # verb fell through to the GET default. Verified live the same day on one endpoint: Type sent
    # the policy list back (a GET), Method returned 400 from Graph body validation (a real POST).
    #
    # The silent fallback is the actual defect. Where GET is invalid it merely confuses; where GET
    # is VALID the caller asking for a write gets 200 and data and thinks the write landed.

    BeforeEach {
        $script:LastPost = $null
        $script:LastGet = $null
        $script:Logs = @()
    }

    It 'refuses <_> used in place of Method instead of silently running a GET' -ForEach @('Type', 'Verb', 'HttpMethod', 'RequestMethod') {
        $Request = [pscustomobject]@{
            Params  = @{ CIPPEndpoint = 'ExecGraphRequest' }
            Headers = @{}
            Query   = [pscustomobject]@{}
            Body    = [pscustomobject]@{
                TenantFilter     = 'contoso.com'
                Endpoint         = 'deviceManagement/virtualEndpoint/provisioningPolicies'
                GraphRequestBody = '{"probe":true}'
            }
        }
        $Request.Body | Add-Member -NotePropertyName $_ -NotePropertyValue 'POST'

        $Response = Invoke-ExecGraphRequest -Request $Request

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Response.Body.Results | Should -Match "the HTTP verb goes in 'Method'"
        # The point of the guard: no Graph call of any kind was made.
        $script:LastGet | Should -BeNullOrEmpty
        $script:LastPost | Should -BeNullOrEmpty
    }

    It 'still honours an explicit Method even when a stray Type is also present' {
        $Request = [pscustomobject]@{
            Params  = @{ CIPPEndpoint = 'ExecGraphRequest' }
            Headers = @{}
            Query   = [pscustomobject]@{}
            Body    = [pscustomobject]@{
                TenantFilter     = 'contoso.com'
                Endpoint         = 'policies/authorizationPolicy'
                Method           = 'POST'
                Type             = 'whatever'
                GraphRequestBody = '{"probe":true}'
            }
        }

        $Response = Invoke-ExecGraphRequest -Request $Request

        $Response.StatusCode | Should -Not -Be ([System.Net.HttpStatusCode]::BadRequest)
        $script:LastPost | Should -Not -BeNullOrEmpty
    }

    It 'leaves a plain GET with no verb parameter alone' {
        $Request = [pscustomobject]@{
            Params  = @{ CIPPEndpoint = 'ExecGraphRequest' }
            Headers = @{}
            Query   = [pscustomobject]@{}
            Body    = [pscustomobject]@{ TenantFilter = 'contoso.com'; Endpoint = 'organization' }
        }

        $Response = Invoke-ExecGraphRequest -Request $Request

        $Response.StatusCode | Should -Not -Be ([System.Net.HttpStatusCode]::BadRequest)
        $script:LastGet | Should -Not -BeNullOrEmpty
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
