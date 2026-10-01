BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SuiteDir = Join-Path $RepoRoot 'Modules/CIPPTests/Public/Tests/Azure'
    $HelperDir = Join-Path $RepoRoot 'Modules/CIPPTests/Public/Helpers'

    function Get-CIPPTestData { param($TenantFilter, $Type) $script:Data[$Type] }
    function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = $Exception.Exception.Message } }
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Add-CippTestResult.ps1')
    Get-ChildItem $HelperDir -Filter *.ps1 | ForEach-Object { . $_.FullName }
    Get-ChildItem (Join-Path $script:SuiteDir 'Azure') -Filter *.ps1 | ForEach-Object { . $_.FullName }

    function New-Nsg {
        param([hashtable[]]$Rules)
        [pscustomobject]@{ name = 'nsg1'; properties = [pscustomobject]@{ securityRules = @($Rules | ForEach-Object {
                        [pscustomobject]@{ name = $_.name ?? 'r'; properties = [pscustomobject]@{
                                direction = 'Inbound'; access = $_.access ?? 'Allow'; priority = 100; protocol = $_.protocol ?? 'Tcp'
                                sourceAddressPrefix = $_.source; sourceAddressPrefixes = @(); destinationPortRange = $_.port; destinationPortRanges = @()
                            }
                        }
                    }) }
        }
    }

    function Set-BaseData {
        $script:Data = @{
            AzureSubscriptions       = @([pscustomobject]@{ subscriptionId = 's1'; displayName = 'Prod'; state = 'Enabled' })
            AzureResources           = @()
            AzureRoleAssignments     = @()
            AzureRoleDefinitions     = @()
            AzureDefender            = @()
            AzureSecurityPosture     = @()
            AzureActivityLogSettings = @()
            AzurePolicy              = @()
            AzureBackupItems         = @()
            AzureResourceConfig      = @()
        }
    }
}

Describe 'Azure test suite' {
    Context 'Suite integrity' {
        It 'lists exactly the AZ_ functions on disk in report.json, each with a description file' {
            $Report = Get-Content (Join-Path $script:SuiteDir 'report.json') -Raw | ConvertFrom-Json
            $OnDisk = @(Get-ChildItem (Join-Path $script:SuiteDir 'Azure') -Filter 'Invoke-CippTestAZ_*.ps1' | ForEach-Object { $_.BaseName -replace '^Invoke-CippTest', '' } | Sort-Object)
            @($Report.AzureTests | Sort-Object) | Should -Be $OnDisk
            foreach ($Id in $OnDisk) {
                Test-Path (Join-Path $script:SuiteDir "Azure/Invoke-CippTest$Id.md") | Should -BeTrue -Because "$Id needs a description"
                Get-Command "Invoke-CippTest$Id" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$Id needs a function of that name"
            }
        }

        It 'every AZ_ test id matches the registered suite pattern and no other suite' {
            . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Get-CippTestSuitePatterns.ps1')
            $Patterns = Get-CippTestSuitePatterns
            $Patterns.Azure | Should -Be 'Invoke-CippTestAZ_*'
            foreach ($Name in @(Get-ChildItem (Join-Path $script:SuiteDir 'Azure') -Filter '*.ps1').BaseName) {
                @($Patterns.GetEnumerator() | Where-Object { $Name -like $_.Value }).Name | Should -Be @('Azure')
            }
        }
    }

    Context 'Runner' {
        BeforeEach { Set-BaseData }

        It 'emits nothing for a tenant without readable subscriptions' {
            $script:Data.AzureSubscriptions = @()
            Invoke-CippTestAZ_STG_01 -Tenant 't' | Should -BeNullOrEmpty
        }

        It 'tags results as TestType Azure and appends the scope line' {
            $R = Invoke-CippTestAZ_RBAC_05 -Tenant 't'
            $R.TestType | Should -Be 'Azure'
            $R.Status | Should -Be 'Passed'
            $R.ResultMarkdown | Should -Match 'Scope: 1 subscription\(s\): Prod'
        }

        It 'turns an evaluator exception into a Failed result instead of throwing' {
            Mock Get-CippAzureTestContext { throw 'boom' }
            $R = Invoke-CippTestAZ_STG_01 -Tenant 't'
            $R.Status | Should -Be 'Failed'
            $R.ResultMarkdown | Should -Match 'boom'
        }

        It 'skips as not applicable when there are no resources of the type' {
            (Invoke-CippTestAZ_KV_01 -Tenant 't').Status | Should -Be 'Skipped'
        }

        It 'fails only the non-compliant resources and lists them' {
            $script:Data.AzureResources = @(
                [pscustomobject]@{ id = '/s/a'; name = 'good'; type = 'microsoft.storage/storageaccounts'; subscriptionId = 's1'; resourceGroup = 'rg'; properties = [pscustomobject]@{ supportsHttpsTrafficOnly = $true } }
                [pscustomobject]@{ id = '/s/b'; name = 'bad'; type = 'microsoft.storage/storageaccounts'; subscriptionId = 's1'; resourceGroup = 'rg'; properties = [pscustomobject]@{ supportsHttpsTrafficOnly = $false } }
            )
            $R = Invoke-CippTestAZ_STG_01 -Tenant 't'
            $R.Status | Should -Be 'Failed'
            $R.ResultMarkdown | Should -Match '1 of 2'
            $R.ResultMarkdown | Should -Match '\| bad \|'
            $R.ResultMarkdown | Should -Not -Match '\| good \|'
        }

        It 'leaves a resource out (not failed) when its settings could not be read' {
            $script:Data.AzureResources = @([pscustomobject]@{ id = '/s/a'; name = 'acct'; kind = 'StorageV2'; type = 'microsoft.storage/storageaccounts'; subscriptionId = 's1'; properties = @{} })
            $script:Data.AzureResourceConfig = @([pscustomobject]@{ id = '/s/a'; config = @{}; errors = @{ blobService = '403' } })
            $R = Invoke-CippTestAZ_STG_07 -Tenant 't'
            $R.Status | Should -Be 'Skipped'
            $R.ResultMarkdown | Should -Match 'Not evaluated'
        }
    }

    Context 'Defender plans' {
        BeforeEach { Set-BaseData }

        It 'fails a subscription where Defender for Cloud was never activated' {
            $script:Data.AzureDefender = @([pscustomobject]@{ subscriptionId = 's1'; securityProviderRegistered = $false; pricings = $null; errors = @{ pricings = 'Subscription Not Registered' } })
            $R = Invoke-CippTestAZ_DFC_07 -Tenant 't'
            $R.Status | Should -Be 'Failed'
            $R.ResultMarkdown | Should -Match 'never been activated'
        }

        It 'only requires a resource plan where that resource type exists' {
            $script:Data.AzureDefender = @([pscustomobject]@{ subscriptionId = 's1'; securityProviderRegistered = $true; pricings = @([pscustomobject]@{ name = 'VirtualMachines'; properties = @{ pricingTier = 'Free' } }); errors = @{} })
            (Invoke-CippTestAZ_DFC_02 -Tenant 't').Status | Should -Be 'Skipped'
            $script:Data.AzureResources = @([pscustomobject]@{ id = '/vm'; name = 'vm1'; type = 'microsoft.compute/virtualmachines'; subscriptionId = 's1' })
            (Invoke-CippTestAZ_DFC_02 -Tenant 't').Status | Should -Be 'Failed'
        }

        It 'passes when the plan is on the Standard tier' {
            $script:Data.AzureDefender = @([pscustomobject]@{ subscriptionId = 's1'; securityProviderRegistered = $true; pricings = @([pscustomobject]@{ name = 'Arm'; properties = @{ pricingTier = 'Standard' } }); errors = @{} })
            (Invoke-CippTestAZ_DFC_07 -Tenant 't').Status | Should -Be 'Passed'
        }
    }

    Context 'RBAC' {
        BeforeEach { Set-BaseData }

        It 'counts owners at subscription and management-group scope, failing above three' {
            $script:Data.AzureRoleAssignments = @(1..4 | ForEach-Object {
                    [pscustomobject]@{ roleName = 'Owner'; assignmentState = 'Active'; scope = $(if ($_ -eq 4) { '/providers/Microsoft.Management/managementGroups/root' } else { '/subscriptions/s1' }); principalId = "p$_"; principalDisplayName = "P$_" }
                })
            (Invoke-CippTestAZ_RBAC_01 -Tenant 't').Status | Should -Be 'Failed'
        }

        It 'does not treat partner ForeignGroup principals as orphaned' {
            $script:Data.AzureRoleAssignments = @(
                [pscustomobject]@{ principalResolved = $false; principalType = 'ForeignGroup'; principalId = 'f'; roleName = 'Owner'; scope = '/subscriptions/s1' }
            )
            (Invoke-CippTestAZ_RBAC_03 -Tenant 't').Status | Should -Be 'Passed'
            $script:Data.AzureRoleAssignments += [pscustomobject]@{ principalResolved = $false; principalType = 'User'; principalId = 'gone'; roleName = 'Reader'; scope = '/subscriptions/s1' }
            (Invoke-CippTestAZ_RBAC_03 -Tenant 't').Status | Should -Be 'Failed'
        }

        It 'fails third-party service principals with Owner but only flags first-party ones' {
            $script:Data.AzureRoleAssignments = @([pscustomobject]@{ principalType = 'ServicePrincipal'; roleName = 'Owner'; scope = '/subscriptions/s1'; principalResolved = $true; principalExternal = $false; principalDisplayName = 'own' })
            (Invoke-CippTestAZ_RBAC_04 -Tenant 't').Status | Should -Be 'Investigate'
            $script:Data.AzureRoleAssignments[0].principalExternal = $true
            (Invoke-CippTestAZ_RBAC_04 -Tenant 't').Status | Should -Be 'Failed'
        }
    }

    Context 'Test-CippAzureNsgExposure' {
        It 'matches RDP open to the internet' {
            @(Test-CippAzureNsgExposure -Nsg (New-Nsg @(@{ source = 'Internet'; port = '3389' })) -Ports 3389 -Protocol Tcp).Count | Should -Be 1
            @(Test-CippAzureNsgExposure -Nsg (New-Nsg @(@{ source = '0.0.0.0/0'; port = '3000-4000' })) -Ports 3389 -Protocol Tcp).Count | Should -Be 1
            @(Test-CippAzureNsgExposure -Nsg (New-Nsg @(@{ source = '*'; port = '*' })) -Ports 3389 -Protocol Tcp).Count | Should -Be 1
        }

        It 'ignores restricted sources, deny rules, other ports and other protocols' {
            @(Test-CippAzureNsgExposure -Nsg (New-Nsg @(@{ source = '203.0.113.10/32'; port = '3389' })) -Ports 3389 -Protocol Tcp).Count | Should -Be 0
            @(Test-CippAzureNsgExposure -Nsg (New-Nsg @(@{ source = 'Internet'; port = '3389'; access = 'Deny' })) -Ports 3389 -Protocol Tcp).Count | Should -Be 0
            @(Test-CippAzureNsgExposure -Nsg (New-Nsg @(@{ source = 'Internet'; port = '443' })) -Ports 3389 -Protocol Tcp).Count | Should -Be 0
            @(Test-CippAzureNsgExposure -Nsg (New-Nsg @(@{ source = 'Internet'; port = '53'; protocol = 'Tcp' })) -Ports 53 -Protocol Udp).Count | Should -Be 0
        }

        It 'with no ports given, matches only allow-all-ports rules' {
            @(Test-CippAzureNsgExposure -Nsg (New-Nsg @(@{ source = 'Internet'; port = '443' }))).Count | Should -Be 0
            @(Test-CippAzureNsgExposure -Nsg (New-Nsg @(@{ source = 'Internet'; port = '0-65535' }))).Count | Should -Be 1
        }
    }
}
