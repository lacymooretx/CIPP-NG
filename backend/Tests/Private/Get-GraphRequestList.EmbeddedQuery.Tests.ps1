# Pester tests for OData options written inside Endpoint (users/x/messages?$filter=...).
# UriBuilder used to parse the embedded query and then overwrite it with the query built from
# $Parameters, so the filter was silently dropped and the whole collection was paged.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    function Get-CIPPTable { param($TableName) }
    function Get-CIPPAzDataTableEntity { param($Context, $Filter, $Property, $First) }
    function Get-Tenants { param($TenantFilter, [switch]$IncludeErrors) }
    function Get-CIPPQueueData { param($Reference) }
    function Get-StringHash { param($String) }
    function New-CippQueueEntry { param($Name, $Link, $Reference, $TotalTasks) }
    function Start-CIPPOrchestrator { param($InputObject) }
    function New-GraphGetRequest { param($uri, $tenantid, $ComplexFilter, $noPagination, $asApp, $Caller, $CountOnly, $noauthcheck) }
    function Test-CIPPGraphEndpointBlocked { param($Uri, $Expand, [switch]$Throw) }
    function Get-CIPPTextReplacement { param($TenantFilter, $Text) }

    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/GraphRequests/Get-GraphRequestList.ps1')

    function Get-RequestedQuery {
        $script:Uris.Count | Should -Be 1
        $Uri = [System.Uri]$script:Uris[0]
        [PSCustomObject]@{
            Path  = $Uri.AbsolutePath
            Query = [System.Web.HttpUtility]::ParseQueryString($Uri.Query)
        }
    }
}

Describe 'Get-GraphRequestList query string embedded in Endpoint' {
    BeforeEach {
        $script:Uris = [System.Collections.Generic.List[string]]::new()
        Mock -CommandName Get-StringHash -MockWith { 'PKHASH' }
        Mock -CommandName Test-CIPPGraphEndpointBlocked -MockWith { }
        Mock -CommandName Get-CIPPTextReplacement -MockWith { $Text -replace '%tenantid%', 'tid-123' }
        Mock -CommandName New-GraphGetRequest -MockWith { $script:Uris.Add($uri); @([PSCustomObject]@{ id = '1' }) }
    }

    It 'keeps $filter/$orderby/$top/$select written inside Endpoint' {
        $null = Get-GraphRequestList -TenantFilter 'x.com' -SkipCache -NoPagination `
            -Endpoint 'users/u@x.com/messages?$filter=receivedDateTime ge 2026-09-30T14:00:00Z&$orderby=receivedDateTime desc&$top=50&$select=subject,from'

        $Req = Get-RequestedQuery
        $Req.Path | Should -Be '/beta/users/u@x.com/messages'
        $Req.Query['$filter'] | Should -Be 'receivedDateTime ge 2026-09-30T14:00:00Z'
        $Req.Query['$orderby'] | Should -Be 'receivedDateTime desc'
        $Req.Query['$top'] | Should -Be '50'
        $Req.Query['$select'] | Should -Be 'from,subject'
    }

    It 'lets an explicit parameter win over the embedded one, and merges the rest' {
        $null = Get-GraphRequestList -TenantFilter 'x.com' -SkipCache -NoPagination `
            -Endpoint 'users?$filter=embedded eq 1&$top=5' -Parameters @{ '$filter' = 'explicit eq 1' }

        $Req = Get-RequestedQuery
        $Req.Path | Should -Be '/beta/users'
        $Req.Query['$filter'] | Should -Be 'explicit eq 1'
        $Req.Query['$top'] | Should -Be '5'
    }

    It 'fills an explicit but empty parameter from the embedded one' {
        $null = Get-GraphRequestList -TenantFilter 'x.com' -SkipCache -NoPagination `
            -Endpoint 'users?$filter=embedded eq 1' -Parameters @{ '$filter' = '' }

        (Get-RequestedQuery).Query['$filter'] | Should -Be 'embedded eq 1'
    }

    It 'does not URL-decode a second time (+ in a UTC offset survives)' {
        $null = Get-GraphRequestList -TenantFilter 'x.com' -SkipCache -NoPagination `
            -Endpoint 'users/u/messages?$filter=receivedDateTime ge 2026-09-30T09:00:00+05:00'

        (Get-RequestedQuery).Query['$filter'] | Should -Be 'receivedDateTime ge 2026-09-30T09:00:00+05:00'
    }

    It 'still resolves %variables% in an embedded filter' {
        $null = Get-GraphRequestList -TenantFilter 'x.com' -SkipCache -NoPagination `
            -Endpoint 'users?$filter=tenant eq ''%tenantid%'''

        $Req = Get-RequestedQuery
        $Req.Path | Should -Be '/beta/users'
        $Req.Query['$filter'] | Should -Be "tenant eq 'tid-123'"
    }

    It 'ignores a trailing ? and empty pairs' {
        $null = Get-GraphRequestList -TenantFilter 'x.com' -SkipCache -NoPagination -Endpoint '/users?&'

        $Req = Get-RequestedQuery
        $Req.Path | Should -Be '/beta/users'
        $Req.Query.Count | Should -Be 0
    }

    It 'leaves an Endpoint without a query unchanged' {
        $null = Get-GraphRequestList -TenantFilter 'x.com' -SkipCache -NoPagination -Endpoint 'users' -Parameters @{ '$top' = '3' }

        $Req = Get-RequestedQuery
        $Req.Path | Should -Be '/beta/users'
        $Req.Query['$top'] | Should -Be '3'
    }

    It 'passes the stripped Endpoint and merged Parameters to the AllTenants queue' {
        Mock -CommandName Get-CIPPTable -MockWith { @{ Context = 'fake' } }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith { @() }
        Mock -CommandName Get-CIPPQueueData -MockWith { $null }
        Mock -CommandName Get-Tenants -MockWith { @([PSCustomObject]@{ defaultDomainName = 'a.com' }) }
        Mock -CommandName New-CippQueueEntry -MockWith { [PSCustomObject]@{ RowKey = 'Q1' } }
        Mock -CommandName Start-CIPPOrchestrator -MockWith { $script:Queued = $InputObject }

        $null = Get-GraphRequestList -TenantFilter 'AllTenants' -Endpoint 'users?$filter=accountEnabled eq true'

        $script:Queued.Batch[0].Endpoint | Should -Be 'users'
        $script:Queued.Batch[0].Parameters['$filter'] | Should -Be 'accountEnabled eq true'
    }
}
