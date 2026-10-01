BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:SuiteDir = Join-Path $RepoRoot 'Modules/CIPPTests/Public/Tests/Azure'
    $script:SavedRootPath = $env:CIPPRootPath
    $env:CIPPRootPath = $RepoRoot
    $Reports = Join-Path $RepoRoot 'Modules/CIPPCore/Public/Reports'

    function Get-Tenants { param($TenantFilter, [switch]$IncludeErrors) [pscustomobject]@{ displayName = 'Contoso'; defaultDomainName = 'contoso.com' } }
    function Get-CippTable { param($tablename) @{ TableName = $tablename } }
    function Get-CIPPAzDataTableEntity { param($TableName, $Filter, $Property) }
    function New-CIPPDbRequest { param($TenantFilter, $Type) }
    . (Join-Path $Reports 'ConvertFrom-CippMarkdownTable.ps1')
    . (Join-Path $Reports 'Get-CIPPAzurePostureReportData.ps1')
    . (Join-Path $Reports 'Get-CIPPReportData.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPTests/Public/Helpers/ConvertTo-CippMarkdownCell.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPTests/Public/Helpers/Format-CippAzureFindingTable.ps1')

    function New-Result {
        param($Id, $Status, $Risk = 'High', $Category = 'Storage', $Markdown = 'Summary line')
        [pscustomobject]@{ PartitionKey = 'contoso.com'; RowKey = $Id; Status = $Status; Risk = $Risk; Category = $Category; Name = "Check $Id"; ResultMarkdown = $Markdown; Timestamp = [datetimeoffset]::UtcNow }
    }
}

AfterAll { $env:CIPPRootPath = $script:SavedRootPath }

Describe 'Azure posture report' {
    Context 'frameworks.json' {
        BeforeAll {
            $script:Fw = Get-Content (Join-Path $script:SuiteDir 'frameworks.json') -Raw | ConvertFrom-Json -AsHashtable
            $script:Report = Get-Content (Join-Path $script:SuiteDir 'report.json') -Raw | ConvertFrom-Json
        }

        It 'tags every test in the suite with at least one known theme, and nothing else' {
            @($script:Fw.tests.Keys | Sort-Object) | Should -Be @($script:Report.AzureTests | Sort-Object)
            foreach ($Id in $script:Fw.tests.Keys) {
                @($script:Fw.tests[$Id]).Count | Should -BeGreaterThan 0 -Because $Id
                foreach ($Theme in $script:Fw.tests[$Id]) { $script:Fw.themes.Contains($Theme) | Should -BeTrue -Because "$Id uses $Theme" }
            }
        }

        It 'gives every theme a name and an entry (possibly empty) for every framework' {
            foreach ($Theme in $script:Fw.themes.Keys) {
                $script:Fw.themes[$Theme].name | Should -Not -BeNullOrEmpty
                foreach ($Key in $script:Fw.frameworks.Keys) { $script:Fw.themes[$Theme].Contains($Key) | Should -BeTrue -Because "$Theme / $Key" }
            }
        }

        It 'keeps the Frameworks block in each test description in step with the mapping' {
            foreach ($Id in $script:Fw.tests.Keys) {
                $Md = Get-Content (Join-Path $script:SuiteDir "Azure/Invoke-CippTest$Id.md") -Raw
                $Md | Should -Match '\*\*Frameworks\*\* \(indicative\)' -Because $Id
                foreach ($Theme in $script:Fw.tests[$Id]) {
                    foreach ($Control in @($script:Fw.themes[$Theme].MCSB)) { $Md | Should -Match ([regex]::Escape($Control)) -Because "$Id should cite MCSB $Control (re-run scripts/sync_az_frameworks.py)" }
                }
            }
        }
    }

    Context 'ConvertFrom-CippMarkdownTable' {
        It 'round-trips cells written by the finding-table formatter, including pipes and backslashes' {
            $Md = "Intro line`n`n" + (Format-CippAzureFindingTable -Rows @([ordered]@{ Resource = 'web | prod'; Finding = 'CONTOSO\svc' }, [ordered]@{ Resource = 'b'; Finding = 'x' }))
            $T = ConvertFrom-CippMarkdownTable -Markdown $Md
            $T.Columns | Should -Be @('Resource', 'Finding')
            $T.Rows.Count | Should -Be 2
            $T.Rows[0] | Should -Be @('web | prod', 'CONTOSO\svc')
        }

        It 'returns null when there is no table' {
            ConvertFrom-CippMarkdownTable -Markdown 'All 3 resource(s) meet the requirement.' | Should -BeNullOrEmpty
        }
    }

    Context 'Get-CIPPAzurePostureReportData' {
        It 'is registered as report type AzurePosture' {
            Mock Get-CIPPAzurePostureReportData { @{ Title = 'stub' } }
            (Get-CIPPReportData -TenantFilter 'contoso.com' -ReportType 'AzurePosture').Title | Should -Be 'stub'
        }

        It 'explains how to onboard when the tenant has no Azure results or subscriptions' {
            $M = Get-CIPPAzurePostureReportData -TenantFilter 'contoso.com'
            $M.Title | Should -Be 'Azure Posture Report'
            @($M.Findings).Count | Should -Be 1
            $M.Findings[0].Status | Should -Be 'info'
            $M.Findings[0].Detail | Should -Match 'Reader'
        }

        It 'scores one finding per category: High/Medium failures fail, Low failures and Investigate warn, skipped ignored' {
            Mock Get-CIPPAzDataTableEntity -ParameterFilter { $TableName -eq 'CippTestResults' } {
                New-Result 'AZ_STG_01' 'Failed' 'High' 'Storage'
                New-Result 'AZ_STG_02' 'Passed' 'High' 'Storage'
                New-Result 'AZ_KV_02' 'Investigate' 'Low' 'Key Vault'
                New-Result 'AZ_VM_01' 'Skipped' 'Medium' 'Compute'
                New-Result 'AZ_LOG_03' 'Passed' 'Low' 'Logging & Monitoring'
            }
            $M = Get-CIPPAzurePostureReportData -TenantFilter 'contoso.com'
            $ByTitle = @{}; foreach ($F in $M.Findings) { $ByTitle[$F.Title] = $F.Status }
            $ByTitle['Storage'] | Should -Be 'fail'
            $ByTitle['Key Vault'] | Should -Be 'warn'
            $ByTitle['Logging & Monitoring'] | Should -Be 'pass'
            $ByTitle.ContainsKey('Compute') | Should -BeFalse
        }

        It 'builds the remediation worklist from each failing check''s findings table' {
            $Md = "1 of 2 resource(s) do not meet the requirement: x`n`n" + (Format-CippAzureFindingTable -Rows @([ordered]@{ Resource = 'acct1'; 'Resource group' = 'rg'; Subscription = 'Prod'; Finding = 'HTTP allowed' }))
            Mock Get-CIPPAzDataTableEntity -ParameterFilter { $TableName -eq 'CippTestResults' } { New-Result 'AZ_STG_01' 'Failed' 'High' 'Storage' $Md }
            $M = Get-CIPPAzurePostureReportData -TenantFilter 'contoso.com'
            $W = $M.Sections | Where-Object { $_.Title -eq 'Remediation worklist' }
            @($W.Rows).Count | Should -Be 1
            $W.Rows[0] | Should -Be @('AZ_STG_01', 'High', 'Failed', 'acct1 (Prod)', 'HTTP allowed')
        }

        It 'lists framework controls with gaps for failing checks' {
            Mock Get-CIPPAzDataTableEntity -ParameterFilter { $TableName -eq 'CippTestResults' } { New-Result 'AZ_STG_01' 'Failed' 'High' 'Storage' }
            $M = Get-CIPPAzurePostureReportData -TenantFilter 'contoso.com'
            $Mcsb = $M.Sections | Where-Object { $_.Title -like 'Framework: Microsoft cloud security benchmark*' }
            $Mcsb.Status | Should -Be 'fail'
            $Row = @($Mcsb.Rows | Where-Object { $_[0] -eq 'DP-3' })
            $Row.Count | Should -Be 1
            $Row[0][1] | Should -Be 'Gaps found'
            $Row[0][5] | Should -Be 'AZ_STG_01'
            @($M.Sections | Where-Object { $_.Title -like 'Framework:*' }).Count | Should -Be 7
        }
    }
}
