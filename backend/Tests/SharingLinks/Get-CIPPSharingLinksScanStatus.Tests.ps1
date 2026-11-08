# Aspendora fork: finished libraries keep their final itemsSeen/mode (saved on the ddone- marker), because the
# checkpoint row the in-flight values come from is deleted when a library finishes.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    function Get-Tenants { param($TenantFilter, [switch]$IncludeErrors) [pscustomobject]@{ defaultDomainName = $TenantFilter } }
    function ConvertTo-CIPPODataFilterValue { param($Value, $Type) $Value }
    function Get-CippTable { param($tablename) @{ TableName = $tablename } }
    function Get-CIPPAzDataTableEntity {
        param($TableName, $Filter, $Property)
        switch -Regex ($Filter) {
            "RowKey eq 'scan'" { return [pscustomobject]@{ ScanId = 's1'; QueueId = 'q1'; StartedUtc = [DateTimeOffset]::UtcNow.AddHours(-1).ToString('o'); Phase = 'drives' } }
            "RowKey eq 'final'" { return $null }
            "'ddone-'" { return $script:DoneRows }
            "'chk-'" { return $script:ChkRows }
            "'drives-'" {
                return [pscustomobject]@{ RowKey = 'drives-site1'; ScanId = 's1'; SiteName = 'Mike OneDrive'; DrivesJson = '[{"id":"d1","name":"Documents","itemCount":10},{"id":"d2","name":"Old","itemCount":5},{"id":"d3","name":"Busy","itemCount":7}]' }
            }
        }
    }
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/SharingLinks/Get-CIPPSharingLinksScanStatus.ps1')
}

Describe 'Get-CIPPSharingLinksScanStatus -Libraries' {
    BeforeAll {
        $script:DoneRows = @(
            [pscustomobject]@{ RowKey = 'ddone-site1~d1'; ScanId = 's1'; Timestamp = [DateTimeOffset]::UtcNow; ItemsSeen = 42; Mode = 'Incremental' }
            [pscustomobject]@{ RowKey = 'ddone-site1~d2'; ScanId = 's1'; Timestamp = [DateTimeOffset]::UtcNow.AddMinutes(-5) }
        )
        $script:ChkRows = @(
            [pscustomobject]@{ RowKey = 'chk-site1~d3'; ScanId = 's1'; StateJson = '{"ItemsSeen":3,"CurrentMode":"Full"}' }
        )
        $script:Result = Get-CIPPSharingLinksScanStatus -TenantFilter 'contoso.com' -Libraries
        $script:Lib = @{}
        foreach ($L in $script:Result.libraries) { $script:Lib[$L.library] = $L }
    }

    It 'reports a finished library''s saved count and mode' {
        $Lib['Documents'].status | Should -Be 'done'
        $Lib['Documents'].itemsSeen | Should -Be 42
        $Lib['Documents'].mode | Should -Be 'Incremental'
    }

    It 'reports null (unknown), not 0, for a done marker written before counts were saved' {
        $Lib['Old'].status | Should -Be 'done'
        $Lib['Old'].itemsSeen | Should -BeNullOrEmpty
        $Lib['Old'].mode | Should -Be ''
    }

    It 'still reports an in-flight library from its checkpoint' {
        $Lib['Busy'].status | Should -Be 'scanning'
        $Lib['Busy'].itemsSeen | Should -Be 3
        $Lib['Busy'].mode | Should -Be 'Full'
    }

    It 'counts totals and orders scanning first' {
        $Result.librariesTotal | Should -Be 3
        $Result.librariesDone | Should -Be 2
        $Result.libraries[0].library | Should -Be 'Busy'
    }
}
