# Aspendora fork (CIPP-64): printer catalogue -> Hudu article, upsert by exact name with read-back.
BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/Printers/Invoke-ExecPrinterCatalogToHudu.ps1')
    # The Functions host supplies `using namespace System.Net`; register the short [HttpStatusCode] here.
    $TypeAccelerators = [PowerShell].Assembly.GetType('System.Management.Automation.TypeAccelerators')
    if (-not ([System.Management.Automation.PSTypeName]'HttpStatusCode').Type) { $TypeAccelerators::Add('HttpStatusCode', [System.Net.HttpStatusCode]) }
    if (-not ('HttpResponseContext' -as [type])) {
        Add-Type -TypeDefinition 'public class HttpResponseContext { public object StatusCode; public object Body; }'
    }
    function Get-CIPPTable { param($TableName) @{ TableName = $TableName } }
    function Get-CIPPAzDataTableEntity {
        param($TableName, $Filter)
        if ($TableName -eq 'Extensionsconfig') { return [pscustomobject]@{ config = (@{ Hudu = @{ Enabled = $script:HuduOn } } | ConvertTo-Json) } }
        $script:Catalog
    }
    function Get-Tenants { param($TenantFilter) [pscustomobject]@{ customerId = 'cid'; defaultDomainName = $TenantFilter } }
    function Get-HuduCompanyId { param($TenantFilter) $script:Company }
    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$Exception" } }
    function Invoke-CippHuduRequest {
        param($Configuration, $Method = 'GET', $Resource, $Params, $Body)
        $script:Calls.Add("$Method $Resource")
        if ($Method -eq 'GET' -and $Resource -eq '/articles') { return @{ articles = @($script:Articles) } }
        if ($Method -in 'POST', 'PUT') { $script:Written = $Body.article; return @{ article = @{ id = 77 } } }
        if ($Method -eq 'GET') { return @{ article = [pscustomobject]@{ name = $script:Written.name; company_id = $script:Written.company_id; content = $script:Written.content } } }
    }
    function Invoke-It { Invoke-ExecPrinterCatalogToHudu -Request @{ Params = @{ CIPPEndpoint = 'ExecPrinterCatalogToHudu' }; Headers = @{}; Body = @{ tenantFilter = 'contoso.com' }; Query = @{} } }
}

Describe 'Invoke-ExecPrinterCatalogToHudu' {
    BeforeEach {
        $script:HuduOn = $true
        $script:Company = [pscustomobject]@{ CompanyId = '12'; CompanyName = 'Contoso' }
        $script:Catalog = @([pscustomobject]@{ Name = 'Front <Desk>'; PrinterType = 'DirectIP'; HostAddress = '10.0.0.5'; DriverName = 'HP'; Location = 'Lobby' })
        $script:Articles = @()
        $script:Calls = [System.Collections.Generic.List[string]]::new()
        $script:Written = $null
    }

    It 'creates the article when none exists, HTML-encodes values, and reads it back' {
        $R = Invoke-It
        "$($R.StatusCode)" | Should -Be 'OK'
        $R.Body.Results | Should -Match "Created 'Printers \(CIPP-managed\)' in Hudu company Contoso with 1 printer"
        $script:Calls | Should -Contain 'POST /articles'
        $script:Calls | Should -Contain 'GET /articles/77'
        $script:Written.company_id | Should -Be 12
        $script:Written.content | Should -Match 'Front &lt;Desk&gt;'
    }

    It 'updates the existing article of the same name in that company, ignoring archived ones and other companies' {
        $script:Articles = @(
            [pscustomobject]@{ id = 5; name = 'Printers (CIPP-managed)'; company_id = 12; archived = $false }
            [pscustomobject]@{ id = 6; name = 'Printers (CIPP-managed)'; company_id = 12; archived = $true }
            [pscustomobject]@{ id = 7; name = 'Printers (CIPP-managed)'; company_id = 99; archived = $false }
        )
        $R = Invoke-It
        $R.Body.Results | Should -Match '^Updated'
        $script:Calls | Should -Contain 'PUT /articles/5'
        $script:Calls | Should -Not -Contain 'POST /articles'
    }

    It 'refuses when Hudu is off or the tenant is unmapped, and writes nothing' {
        $script:HuduOn = $false
        (Invoke-It).Body.Results | Should -Match 'Hudu extension is not enabled'
        $script:HuduOn = $true; $script:Company = $null
        (Invoke-It).Body.Results | Should -Match 'not mapped to a Hudu company'
        $script:Calls | Should -BeNullOrEmpty
    }
}
