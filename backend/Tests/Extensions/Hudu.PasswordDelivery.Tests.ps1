# Pester tests for the Hudu password-delivery path (IT Glue -> Hudu migration, 2026-10):
# Set-CippHuduUserPassword (upsert 'M365 - <UPN>'), Get-CippHuduUserPassword (welcome packet read),
# Find-CippHuduPersonAsset (attach to the People asset), Invoke-CippHuduRequest (URL/headers), and the
# destination resolution in Get-CIPPPasswordDeliveryOptions.
# Hudu silently ignores unknown query params, so several tests feed rows from the wrong company,
# archived rows and near-miss names to prove the client-side re-check.

BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $HuduDir = Join-Path $BackendRoot 'Modules/CippExtensions/Public/Hudu'

    function Get-CIPPTable { param([string]$TableName) @{ TableName = $TableName } }
    function Get-CIPPAzDataTableEntity { param($TableName, $Filter) }
    function Get-Tenants { param($TenantFilter, [switch]$IncludeErrors) }
    function Get-ExtensionMapping { param($Extension) }
    function Get-ExtensionAPIKey { param($Extension, [switch]$Force) 'test-key' }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData, $headers) }
    function Get-PwPushConfiguration { }

    . (Join-Path $HuduDir 'Invoke-CippHuduRequest.ps1')
    . (Join-Path $HuduDir 'Get-HuduCompanyId.ps1')
    . (Join-Path $HuduDir 'Find-CippHuduPersonAsset.ps1')
    . (Join-Path $HuduDir 'Set-CippHuduUserPassword.ps1')
    . (Join-Path $HuduDir 'Get-CippHuduUserPassword.ps1')
    . (Join-Path $BackendRoot 'Modules/CIPPCore/Public/Get-CIPPPasswordDeliveryOptions.ps1')

    $script:Upn = 'jane@client.com'
    $script:EnabledConfig = [pscustomobject]@{ config = (@{ Hudu = @{ Enabled = $true; BaseURL = 'https://hudu.example.com/' } } | ConvertTo-Json -Depth 5) }

    function New-PersonAsset { param($Id, $Email, $Company = 3, $Layout = 1, $Archived = $false, $PrimaryMail = $null)
        [pscustomobject]@{ id = $Id; company_id = $Company; asset_layout_id = $Layout; archived = $Archived; primary_mail = $PrimaryMail
            fields = @([pscustomobject]@{ label = 'Email Address'; value = $Email }) }
    }
}

Describe 'Invoke-CippHuduRequest' {
    It 'builds /api/v1 URL with escaped query, api key header and JSON body' {
        Mock Invoke-RestMethod { $script:Req = @{ Uri = $Uri; Headers = $Headers; Body = $Body; Method = $Method }; 'ok' }
        $Cfg = [pscustomobject]@{ Hudu = [pscustomobject]@{ BaseURL = 'https://hudu.example.com/' } }
        Invoke-CippHuduRequest -Configuration $Cfg -Method POST -Resource '/asset_passwords' -Params @{ name = 'M365 - a@b.com'; company_id = 3 } -Body @{ asset_password = @{ name = 'x' } } | Should -Be 'ok'
        $script:Req.Uri.OriginalString | Should -Be 'https://hudu.example.com/api/v1/asset_passwords?company_id=3&name=M365%20-%20a%40b.com'
        $script:Req.Headers['x-api-key'] | Should -Be 'test-key'
        ($script:Req.Body | ConvertFrom-Json).asset_password.name | Should -Be 'x'
    }

    It 'refuses to run without a base URL' {
        { Invoke-CippHuduRequest -Configuration ([pscustomobject]@{ Hudu = @{} }) -Resource '/x' } | Should -Throw '*base URL*'
    }
}

Describe 'Set-CippHuduUserPassword' {
    BeforeEach {
        Mock Get-CIPPAzDataTableEntity { $script:EnabledConfig } -ParameterFilter { -not $Filter }
        Mock Get-CIPPAzDataTableEntity { [pscustomobject]@{ IntegrationId = '1' } } -ParameterFilter { $Filter -like "*HuduFieldMapping*" }
        Mock Get-Tenants { [pscustomobject]@{ customerId = 'cust-1'; defaultDomainName = 'client.com' } }
        Mock Get-ExtensionMapping { @([pscustomobject]@{ RowKey = 'cust-1'; IntegrationId = '3'; IntegrationName = 'Client Co' }) }
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        $script:Passwords = @()
        $script:People = @()
        Mock Invoke-CippHuduRequest {
            if (-not $Method) { $Method = 'GET' }
            $script:Calls.Add([pscustomobject]@{ Method = $Method; Resource = $Resource; Params = $Params; Body = $Body })
            if ($Method -eq 'GET' -and $Resource -eq '/asset_passwords') { return [pscustomobject]@{ asset_passwords = $script:Passwords } }
            if ($Method -eq 'GET' -and $Resource -eq '/assets') { return [pscustomobject]@{ assets = $script:People } }
            if ($Method -eq 'POST') { return [pscustomobject]@{ asset_password = [pscustomobject]@{ id = 900; url = 'https://hudu.example.com/passwords/new' } } }
            if ($Method -eq 'PUT') { return [pscustomobject]@{ asset_password = [pscustomobject]@{ id = 42; url = 'https://hudu.example.com/passwords/upd' } } }
        }
    }

    It 'does nothing when the Hudu extension is disabled' {
        Mock Get-CIPPAzDataTableEntity { [pscustomobject]@{ config = (@{ Hudu = @{ Enabled = $false } } | ConvertTo-Json) } } -ParameterFilter { -not $Filter }
        $R = Set-CippHuduUserPassword -TenantFilter 'client.com' -UserPrincipalName $Upn -Password 'pw'
        $R.Success | Should -BeFalse
        $R.Message | Should -Match 'not enabled'
        Should -Invoke Invoke-CippHuduRequest -Times 0
    }

    It 'reports an unmapped tenant instead of writing' {
        Mock Get-ExtensionMapping { @() }
        $R = Set-CippHuduUserPassword -TenantFilter 'client.com' -UserPrincipalName $Upn -Password 'pw'
        $R.Success | Should -BeFalse
        $R.Message | Should -Match 'not mapped to a Hudu company'
        Should -Invoke Invoke-CippHuduRequest -Times 0
    }

    It 'creates the record and attaches it to the one matching person' {
        $script:People = @(
            (New-PersonAsset -Id 10 -Email 'Jane@Client.com'),
            (New-PersonAsset -Id 11 -Email 'other@client.com'),
            (New-PersonAsset -Id 12 -Email $Upn -Company 99)
        )
        $R = Set-CippHuduUserPassword -TenantFilter 'client.com' -UserPrincipalName $Upn -Password 'pw' -DisplayName 'Jane Doe' -Notes 'note'
        $R.Success | Should -BeTrue
        $R.Action | Should -Be 'created'
        $R.PasswordId | Should -Be 900
        $R.PersonAssetId | Should -Be 10
        $Post = $script:Calls | Where-Object Method -eq 'POST'
        $Post.Resource | Should -Be '/asset_passwords'
        $Body = $Post.Body.asset_password
        $Body.name | Should -Be "M365 - $Upn"
        $Body.username | Should -Be $Upn
        $Body.password | Should -Be 'pw'
        $Body.company_id | Should -Be 3
        $Body.passwordable_type | Should -Be 'Asset'
        $Body.passwordable_id | Should -Be 10
        $Body.description | Should -Be "Jane Doe`n`nnote"
    }

    It 'updates the existing record in place, ignoring archived, other-company and near-miss rows' {
        $script:Passwords = @(
            [pscustomobject]@{ id = 41; name = "M365 - $Upn"; company_id = 3; archived = $true; updated_at = '2026-10-10T00:00:00Z' },
            [pscustomobject]@{ id = 43; name = "M365 - $Upn"; company_id = 7; archived = $false; updated_at = '2026-10-10T00:00:00Z' },
            [pscustomobject]@{ id = 44; name = 'M365 - jane@client.com.old'; company_id = 3; archived = $false; updated_at = '2026-10-10T00:00:00Z' },
            [pscustomobject]@{ id = 42; name = "M365 - $Upn"; company_id = 3; archived = $false; updated_at = '2026-10-01T00:00:00Z'; url = 'u' }
        )
        $R = Set-CippHuduUserPassword -TenantFilter 'client.com' -UserPrincipalName $Upn -Password 'pw2'
        $R.Action | Should -Be 'updated'
        $R.PasswordId | Should -Be 42
        ($script:Calls | Where-Object Method -eq 'PUT').Resource | Should -Be '/asset_passwords/42'
        Should -Invoke Invoke-CippHuduRequest -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }

    It 'does not attach (or detach) when two people share the address' {
        $script:People = @((New-PersonAsset -Id 10 -Email $Upn), (New-PersonAsset -Id 20 -Email $Upn -PrimaryMail $Upn))
        $R = Set-CippHuduUserPassword -TenantFilter 'client.com' -UserPrincipalName $Upn -Password 'pw'
        $R.Success | Should -BeTrue
        $R.PersonAssetId | Should -BeNullOrEmpty
        $Body = ($script:Calls | Where-Object Method -eq 'POST').Body.asset_password
        $Body.Contains('passwordable_id') | Should -BeFalse
    }

    It 'returns a failure result instead of throwing when Hudu errors' {
        Mock Invoke-CippHuduRequest { throw 'boom' } -ParameterFilter { $Method -eq 'POST' }
        $R = Set-CippHuduUserPassword -TenantFilter 'client.com' -UserPrincipalName $Upn -Password 'pw'
        $R.Success | Should -BeFalse
        $R.Message | Should -Match 'boom'
    }
}

Describe 'Get-CippHuduUserPassword' {
    BeforeEach {
        Mock Get-CIPPAzDataTableEntity { $script:EnabledConfig } -ParameterFilter { -not $Filter }
        Mock Get-Tenants { [pscustomobject]@{ customerId = 'cust-1' } }
        Mock Get-ExtensionMapping { @([pscustomobject]@{ RowKey = 'cust-1'; IntegrationId = '3'; IntegrationName = 'Client Co' }) }
        $script:ByName = @()
        $script:All = @()
        Mock Invoke-CippHuduRequest {
            if ($Params.ContainsKey('name')) { return [pscustomobject]@{ asset_passwords = $script:ByName } }
            return [pscustomobject]@{ asset_passwords = $script:All }
        }
    }

    It 'reads the portal record by name' {
        $script:ByName = @([pscustomobject]@{ id = 5; name = "M365 - $Upn"; company_id = 3; archived = $false; password = 'secret'; url = 'u5'; updated_at = '2026-10-10T01:00:00Z' })
        $R = Get-CippHuduUserPassword -TenantFilter 'client.com' -UserPrincipalName $Upn
        $R.Success | Should -BeTrue
        $R.Password | Should -Be 'secret'
        $R.IsPortalRecord | Should -BeTrue
        $R.Url | Should -Be 'u5'
        $R.Message | Should -BeNullOrEmpty
    }

    It 'falls back to the username and warns' {
        $script:All = @(
            [pscustomobject]@{ id = 6; name = 'Jane O365'; username = $Upn; company_id = 3; archived = $false; password = 'old'; updated_at = '2026-01-01T00:00:00Z' },
            [pscustomobject]@{ id = 7; name = 'Jane M365'; username = $Upn; company_id = 3; archived = $false; password = 'new'; updated_at = '2026-09-01T00:00:00Z' }
        )
        $R = Get-CippHuduUserPassword -TenantFilter 'client.com' -UserPrincipalName $Upn
        $R.Success | Should -BeTrue
        $R.Password | Should -Be 'new'
        $R.IsPortalRecord | Should -BeFalse
        $R.OtherMatchCount | Should -Be 1
        $R.Message | Should -Match '2 Hudu records'
    }

    It 'says so when nothing matches' {
        $R = Get-CippHuduUserPassword -TenantFilter 'client.com' -UserPrincipalName $Upn
        $R.Success | Should -BeFalse
        $R.Message | Should -Match 'No Hudu password record'
    }
}

Describe 'Get-CIPPPasswordDeliveryOptions - documentation destinations' {
    BeforeAll {
        function New-PwConfig { param($ItgDefault = $true, $HuduDefault = $null, $ItgOn = $true, $HuduOn = $true)
            $Cfg = [pscustomobject]@{ Enabled = $true; DispatchEmailUser = $true; DispatchTextUser = $true; DispatchSupervisor = $false; DocumentInITGlue = $ItgDefault
                FullConfiguration = [pscustomobject]@{ ITGlue = [pscustomobject]@{ Enabled = $ItgOn }; Hudu = [pscustomobject]@{ Enabled = $HuduOn } } }
            if ($null -ne $HuduDefault) { $Cfg | Add-Member -NotePropertyName DocumentInHudu -NotePropertyValue $HuduDefault }
            $Cfg
        }
    }

    It 'Hudu follows the IT Glue default when no Hudu default has been saved' {
        Mock Get-PwPushConfiguration { New-PwConfig -ItgDefault $true }
        $R = Get-CIPPPasswordDeliveryOptions
        $R.DocumentInHudu | Should -BeTrue
        $R.DocumentInITGlue | Should -BeTrue
    }

    It 'an explicit Hudu default wins' {
        Mock Get-PwPushConfiguration { New-PwConfig -ItgDefault $true -HuduDefault $false }
        (Get-CIPPPasswordDeliveryOptions).DocumentInHudu | Should -BeFalse
    }

    It 'an older caller sending only DocumentInITGlue=false turns Hudu off too' {
        Mock Get-PwPushConfiguration { New-PwConfig -HuduDefault $true }
        $R = Get-CIPPPasswordDeliveryOptions -Delivery ([pscustomobject]@{ DocumentInITGlue = $false })
        $R.DocumentInHudu | Should -BeFalse
        $R.DocumentInITGlue | Should -BeFalse
    }

    It 'a per-run DocumentInHudu wins over DocumentInITGlue' {
        Mock Get-PwPushConfiguration { New-PwConfig -HuduDefault $false }
        $R = Get-CIPPPasswordDeliveryOptions -Delivery ([pscustomobject]@{ DocumentInITGlue = $false; DocumentInHudu = $true })
        $R.DocumentInHudu | Should -BeTrue
    }

    It 'a disabled IT Glue extension stops IT Glue writes even when the caller asks for them' {
        Mock Get-PwPushConfiguration { New-PwConfig -ItgOn $false }
        $R = Get-CIPPPasswordDeliveryOptions -Delivery ([pscustomobject]@{ DocumentInITGlue = $true })
        $R.DocumentInITGlue | Should -BeFalse
        $R.DocumentInHudu | Should -BeTrue
    }

    It 'a disabled Hudu extension stops Hudu writes' {
        Mock Get-PwPushConfiguration { New-PwConfig -HuduOn $false -HuduDefault $true }
        (Get-CIPPPasswordDeliveryOptions).DocumentInHudu | Should -BeFalse
    }
}
