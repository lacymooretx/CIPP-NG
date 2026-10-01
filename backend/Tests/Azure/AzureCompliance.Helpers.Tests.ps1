BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $AzureDir = Join-Path $RepoRoot 'Modules/CIPPCore/Public/Azure'

    function Get-GraphToken { param($tenantid, $scope, $AsApp) @{ Authorization = 'Bearer test' } }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData, $headers) }
    function New-CIPPDbRequest { param($TenantFilter, $Type, $Fields) }
    function Add-CIPPDbItem {
        param($TenantFilter, $Type, [Parameter(ValueFromPipeline)]$InputObject, [switch]$AddCount, [switch]$ClearOnEmpty)
        begin { $script:Written = [System.Collections.Generic.List[object]]::new() }
        process { if ($null -ne $InputObject) { $script:Written.Add($InputObject) } }
        end { $script:WriteCall = @{ Type = $Type; ClearOnEmpty = [bool]$ClearOnEmpty; AddCount = [bool]$AddCount } }
    }
    function Get-Tenants { param($TenantFilter, [switch]$IncludeErrors) }
    function New-GraphPOSTRequest { param($uri, $tenantid, $body, $AsApp) }

    # Scripted stand-in for Invoke-CIPPRestMethod: pops one response per call and sets the
    # caller's status/header variables the way the real wrapper does (Set-Variable -Scope 1).
    function Invoke-CIPPRestMethod {
        param($Uri, $Method, $Headers, $ContentType, $Body, [switch]$SkipHttpErrorCheck, $StatusCodeVariable, $ResponseHeadersVariable)
        $script:Requests.Add([pscustomobject]@{ Uri = [string]$Uri; Method = $Method; Body = $Body })
        $Next = $script:Responses.Dequeue()
        if ($StatusCodeVariable) { Set-Variable -Scope 1 -Name $StatusCodeVariable -Value $Next.Status }
        if ($ResponseHeadersVariable) { Set-Variable -Scope 1 -Name $ResponseHeadersVariable -Value ($Next.Headers ?? @{}) }
        $Next.Body
    }
    function Start-Sleep { param($Seconds) $script:Slept += $Seconds }

    Get-ChildItem $AzureDir -Filter *.ps1 | ForEach-Object { . $_.FullName }

    function Set-Responses { param([object[]]$List) $script:Responses = [System.Collections.Generic.Queue[object]]::new(); foreach ($r in $List) { $script:Responses.Enqueue($r) } }
}

Describe 'Azure compliance helpers' {
    BeforeEach {
        $script:Requests = [System.Collections.Generic.List[object]]::new()
        $script:Slept = 0
    }

    Describe 'New-CIPPAzureRequest' {
        It 'prefixes relative paths with the ARM host' {
            Set-Responses @(@{ Status = 200; Body = [pscustomobject]@{ value = @() } })
            $null = New-CIPPAzureRequest -TenantFilter 'contoso.com' -Uri '/subscriptions?api-version=2022-12-01'
            $script:Requests[0].Uri | Should -Be 'https://management.azure.com/subscriptions?api-version=2022-12-01'
        }

        It 'follows ARM nextLink paging and unwraps value' {
            Set-Responses @(
                @{ Status = 200; Body = [pscustomobject]@{ value = @(1, 2); nextLink = 'https://management.azure.com/page2' } }
                @{ Status = 200; Body = [pscustomobject]@{ value = @(3) } }
            )
            $Result = @(New-CIPPAzureRequest -TenantFilter 'contoso.com' -Uri '/x')
            $Result | Should -Be @(1, 2, 3)
            $script:Requests[1].Uri | Should -Be 'https://management.azure.com/page2'
        }

        It 'returns a single object when there is no value array' {
            Set-Responses @(@{ Status = 200; Body = [pscustomobject]@{ name = 'default'; properties = @{ a = 1 } } })
            (New-CIPPAzureRequest -TenantFilter 'contoso.com' -Uri '/x').name | Should -Be 'default'
        }

        It 'retries 429 honouring Retry-After, then succeeds' {
            Set-Responses @(
                @{ Status = 429; Headers = @{ 'Retry-After' = @('3') }; Body = $null }
                @{ Status = 200; Body = [pscustomobject]@{ value = @('ok') } }
            )
            New-CIPPAzureRequest -TenantFilter 'contoso.com' -Uri '/x' | Should -Be 'ok'
            $script:Slept | Should -Be 3
        }

        It 'throws ARM error text on a non-retryable failure' {
            Set-Responses @(@{ Status = 403; Body = [pscustomobject]@{ error = [pscustomobject]@{ code = 'AuthorizationFailed'; message = 'no access' } } })
            { New-CIPPAzureRequest -TenantFilter 'contoso.com' -Uri '/x' } | Should -Throw '*403*AuthorizationFailed: no access*'
        }
    }

    Describe 'Search-CIPPAzureResourceGraph' {
        It 'pages with $skipToken and scopes to the given subscriptions' {
            Set-Responses @(
                @{ Status = 200; Body = [pscustomobject]@{ data = @(@{ id = 'a' }); '$skipToken' = 'tok' } }
                @{ Status = 200; Body = [pscustomobject]@{ data = @(@{ id = 'b' }) } }
            )
            $Rows = @(Search-CIPPAzureResourceGraph -TenantFilter 'contoso.com' -Query 'resources' -Subscriptions @('s1'))
            $Rows.id | Should -Be @('a', 'b')
            $Second = $script:Requests[1].Body | ConvertFrom-Json
            $Second.options.'$skipToken' | Should -Be 'tok'
            $Second.subscriptions | Should -Be @('s1')
            $script:Requests[0].Method | Should -Be 'POST'
        }
    }

    Describe 'Set-CIPPAzureCacheItems' {
        It 'clears the type without running the collector when no subscription is readable' {
            Mock New-CIPPDbRequest { @() }
            $script:Ran = $false
            Set-CIPPAzureCacheItems -TenantFilter 'contoso.com' -Type 'AzureResources' -ScriptBlock { $script:Ran = $true }
            $script:Ran | Should -BeFalse
            $script:WriteCall.ClearOnEmpty | Should -BeTrue
            $script:Written.Count | Should -Be 0
        }

        It 'passes only enabled subscription ids and writes the items authoritatively' {
            Mock New-CIPPDbRequest { @([pscustomobject]@{ subscriptionId = 's1'; state = 'Enabled' }, [pscustomobject]@{ subscriptionId = 's2'; state = 'Disabled' }) }
            Set-CIPPAzureCacheItems -TenantFilter 'contoso.com' -Type 'AzureResources' -ScriptBlock { param($Ids) foreach ($i in $Ids) { [pscustomobject]@{ id = "r-$i" } } }
            $script:Written.id | Should -Be @('r-s1')
            $script:WriteCall.Type | Should -Be 'AzureResources'
            $script:WriteCall.ClearOnEmpty | Should -BeTrue
        }

        It 'does not overwrite cached data when the collector throws' {
            Mock New-CIPPDbRequest { @([pscustomobject]@{ subscriptionId = 's1'; state = 'Enabled' }) }
            $script:WriteCall = $null
            { Set-CIPPAzureCacheItems -TenantFilter 'contoso.com' -Type 'AzureResources' -ScriptBlock { throw 'ARM down' } } | Should -Throw '*ARM down*'
            $script:WriteCall | Should -BeNullOrEmpty
        }
    }

    Describe 'Resolve-CIPPAzurePrincipals' {
        BeforeEach {
            Mock Get-Tenants { [pscustomobject]@{ customerId = 'tenant-1' } }
            Mock New-GraphPOSTRequest {
                [pscustomobject]@{ value = @(
                        [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1'; displayName = 'Member'; userType = 'Member' }
                        [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = 'u2'; displayName = 'Guest'; userType = 'Guest' }
                        [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'sp1'; displayName = 'Vendor'; appOwnerOrganizationId = 'vendor-tenant' }
                        [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'sp2'; displayName = 'Own'; appOwnerOrganizationId = 'tenant-1' }
                        [pscustomobject]@{ '@odata.type' = '#microsoft.graph.servicePrincipal'; id = 'sp3'; displayName = 'MS'; appOwnerOrganizationId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' }
                    ) }
            }
        }

        It 'flags guests and third-party service principals as external, and leaves deleted ids unresolved' {
            $R = Resolve-CIPPAzurePrincipals -TenantFilter 'contoso.com' -PrincipalIds @('u1', 'u2', 'sp1', 'sp2', 'sp3', 'gone', 'u1')
            $R['u1'].external | Should -BeFalse
            $R['u2'].external | Should -BeTrue
            $R['sp1'].external | Should -BeTrue
            $R['sp2'].external | Should -BeFalse
            $R['sp3'].external | Should -BeFalse
            $R['sp1'].objectType | Should -Be 'servicePrincipal'
            $R.ContainsKey('gone') | Should -BeFalse
            Should -Invoke New-GraphPOSTRequest -Times 1 -Exactly
        }

        It 'makes no Graph call for an empty id list' {
            $R = Resolve-CIPPAzurePrincipals -TenantFilter 'contoso.com' -PrincipalIds @()
            $R.Count | Should -Be 0
            Should -Invoke New-GraphPOSTRequest -Times 0 -Exactly
        }
    }

    Describe 'Get-CIPPAzureBuiltInRoleName' {
        It 'maps well-known built-in role GUIDs case-insensitively' {
            Get-CIPPAzureBuiltInRoleName -RoleDefinitionGuid '8E3AF657-A8FF-443C-A75C-2FE8C4BCB635' | Should -Be 'Owner'
            Get-CIPPAzureBuiltInRoleName -RoleDefinitionGuid 'nope' | Should -BeNullOrEmpty
        }
    }
}
