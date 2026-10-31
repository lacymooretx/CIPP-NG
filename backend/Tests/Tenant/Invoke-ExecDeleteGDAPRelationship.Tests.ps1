# Aspendora fork: an unaccepted invite (status 'created') cannot be terminated, only deleted with its
# ETag; every other relationship is still terminated through a /requests call.

BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $BackendRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Tenant/GDAP/Invoke-ExecDeleteGDAPRelationship.ps1'

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }

    function New-GraphGetRequest { param($uri, $tenantid, $NoAuthCheck) $script:Rel }
    function New-GraphPostRequest {
        param($uri, $tenantid, $NoAuthCheck, $type, $body, $AddedHeaders)
        $script:Calls.Add([pscustomobject]@{ Uri = $uri; Type = $type; Body = $body; Headers = $AddedHeaders })
    }
    function Write-LogMessage { param($headers, $API, $message, $Sev, $LogData) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$Exception" } }

    . $FunctionPath
}

Describe 'Invoke-ExecDeleteGDAPRelationship' {
    BeforeEach {
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        $env:TenantID = 'partner'
        $script:Request = [pscustomobject]@{ Params = @{ CIPPEndpoint = 'ExecDeleteGDAPRelationship' }; Headers = @{}; Query = @{ GDAPId = 'rel-1' }; Body = $null }
    }

    It 'deletes an unaccepted invite with its ETag' {
        $script:Rel = [pscustomobject]@{ id = 'rel-1'; displayName = 'Old invite'; status = 'created'; '@odata.etag' = 'W/"abc"' }
        $R = Invoke-ExecDeleteGDAPRelationship -Request $script:Request
        $R.StatusCode | Should -Be 200
        $script:Calls.Count | Should -Be 1
        $script:Calls[0].Type | Should -Be 'DELETE'
        $script:Calls[0].Uri | Should -Match 'delegatedAdminRelationships/rel-1$'
        $script:Calls[0].Headers.'If-Match' | Should -Be 'W/"abc"'
        $R.Body.Results | Should -Match 'Delete requested'
    }

    It 'terminates an active relationship' {
        $script:Rel = [pscustomobject]@{ id = 'rel-1'; status = 'active'; '@odata.etag' = 'W/"x"' }
        $R = Invoke-ExecDeleteGDAPRelationship -Request $script:Request
        $R.StatusCode | Should -Be 200
        $script:Calls[0].Type | Should -Be 'POST'
        $script:Calls[0].Uri | Should -Match '/requests$'
        $script:Calls[0].Body | Should -Match 'terminate'
    }
}
