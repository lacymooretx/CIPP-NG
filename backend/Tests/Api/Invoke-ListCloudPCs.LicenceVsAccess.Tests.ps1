# The Cloud PC API answers "this tenant has no Windows 365 licence" with the SAME
# "Access is denied to the requested resource" it uses for a genuine permission fault - it does so
# even for servicePlans, a static global catalogue. Nothing in the response distinguishes them, so
# an operator reads a licence gap as broken consent and goes off repairing permissions that were
# already correct. That happened before this endpoint existed.
#
# These tests pin the distinction: unlicensed -> NotLicensed (not an error), licensed-and-denied ->
# AccessDenied naming the two fixable causes, and a non-denial error still throws rather than being
# laundered into a tidy "no licence" answer.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))

    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
    }

    function Write-LogMessage { param($headers, $API, $tenant, $message, $Sev, $LogData) $script:Logs += $message }
    function Get-CippException { param($Exception) @{ NormalizedError = $Exception.Exception.Message } }

    function New-GraphGetRequest {
        param($uri, $tenantid, $AsApp, $ErrorAction)
        $script:Calls += [pscustomobject]@{ Uri = $uri; AsApp = $AsApp }
        if ($uri -match 'subscribedSkus') { return $script:SkuResponse }
        if ($script:GraphThrows) { throw $script:GraphThrows }
        return $script:CloudPcResponse
    }

    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/CloudPC/Test-CIPPCloudPCLicensed.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/CloudPC/Get-CIPPCloudPCCollection.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/Endpoint/CloudPC/Invoke-ListCloudPCs.ps1')

    function New-TestRequest {
        [pscustomobject]@{
            Params  = @{ CIPPEndpoint = 'ListCloudPCs' }
            Headers = @{}
            Query   = [pscustomobject]@{ tenantFilter = 'contoso.com' }
            Body    = [pscustomobject]@{}
        }
    }
    $script:DeniedMessage = 'Access is denied to the requested resource.'
}

Describe 'ListCloudPCs licence-versus-access classification' {
    BeforeEach {
        $script:Logs = @()
        $script:Calls = @()
        $script:GraphThrows = $null
        $script:SkuResponse = @()
        $script:CloudPcResponse = @()
    }

    It 'reads the Cloud PC tree app-only, never delegated' {
        $script:CloudPcResponse = @([pscustomobject]@{ displayName = 'CPC-test'; userPrincipalName = 'a@contoso.com' })
        $null = Invoke-ListCloudPCs -Request (New-TestRequest)

        $CloudPcCall = $script:Calls | Where-Object { $_.Uri -match 'virtualEndpoint/cloudPCs' }
        $CloudPcCall | Should -Not -BeNullOrEmpty
        $CloudPcCall.AsApp | Should -BeTrue
    }

    It 'returns the Cloud PCs on a healthy tenant' {
        $script:CloudPcResponse = @(
            [pscustomobject]@{ displayName = 'CPC-lacy'; userPrincipalName = 'lacy@contoso.com'; servicePlanName = 'Cloud PC Enterprise 16vCPU/64GB/512GB' }
        )
        $Response = Invoke-ListCloudPCs -Request (New-TestRequest)
        $Rows = @($Response.Body)

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $Rows.Count | Should -Be 1
        $Rows[0].displayName | Should -Be 'CPC-lacy'
        $Rows[0].cloudPcState | Should -Be 'Ok'
    }

    It 'reports NotLicensed - not an error - when the tenant owns no Windows 365 SKU' {
        $script:GraphThrows = $script:DeniedMessage
        $script:SkuResponse = @([pscustomobject]@{ skuPartNumber = 'SPB' })

        $Response = Invoke-ListCloudPCs -Request (New-TestRequest)
        $Rows = @($Response.Body)

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $Rows[0].cloudPcState | Should -Be 'NotLicensed'
        $Rows[0].cloudPcStateMessage | Should -Match 'not a permission problem'
    }

    It 'reports AccessDenied when the tenant IS licensed but the call is still denied' {
        $script:GraphThrows = $script:DeniedMessage
        $script:SkuResponse = @([pscustomobject]@{ skuPartNumber = 'CPC_E_16C_64GB_512GB'; prepaidUnits = [pscustomobject]@{ enabled = 2 } })

        $Rows = @((Invoke-ListCloudPCs -Request (New-TestRequest)).Body)

        $Rows[0].cloudPcState | Should -Be 'AccessDenied'
        $Rows[0].cloudPcStateMessage | Should -Match 'CloudPC.ReadWrite.All'
        $Rows[0].cloudPcStateMessage | Should -Match 'restart'
    }

    It 'recognises the descriptive SKU form a live tenant actually returns' {
        # aspendora.com reports 'Windows_365_Enterprise_16_vCPU,_64_GB,_512_GB', not CPC_*.
        # Matching only CPC_ would call our one licensed tenant unlicensed.
        Test-CIPPCloudPCLicensed -TenantFilter 'contoso.com' | Out-Null
        $script:SkuResponse = @([pscustomobject]@{ skuPartNumber = 'Windows_365_Enterprise_16_vCPU,_64_GB,_512_GB'; prepaidUnits = [pscustomobject]@{ enabled = 2 } })
        Test-CIPPCloudPCLicensed -TenantFilter 'contoso.com' | Should -BeTrue
    }

    It 'treats a SKU with zero enabled units as not licensed' {
        $script:SkuResponse = @([pscustomobject]@{ skuPartNumber = 'CPC_E_2C_8GB_128GB'; prepaidUnits = [pscustomobject]@{ enabled = 0 } })
        Test-CIPPCloudPCLicensed -TenantFilter 'contoso.com' | Should -BeFalse
    }

    It 'does not launder a non-denial error into a licence answer' {
        # A malformed request or a 5xx means what it says. Only a denial is ambiguous.
        $script:GraphThrows = 'The request is throttled. Retry after 30 seconds.'
        $script:SkuResponse = @()

        $Response = Invoke-ListCloudPCs -Request (New-TestRequest)
        $Rows = @($Response.Body)

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
        $Rows[0].cloudPcState | Should -Be 'Error'
        $Rows[0].cloudPcStateMessage | Should -Match 'throttled'
    }

    It 'requires a tenantFilter' {
        $Request = New-TestRequest
        $Request.Query = [pscustomobject]@{}
        $Response = Invoke-ListCloudPCs -Request $Request

        $Response.StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
        @($Response.Body)[0].cloudPcStateMessage | Should -Match 'tenantFilter is required'
    }
}
