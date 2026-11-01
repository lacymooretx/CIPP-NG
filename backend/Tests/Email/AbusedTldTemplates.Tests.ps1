# Aspendora fork (Vikunja CIPP-30): the shipped abused-TLD TABL templates.
# Guards the importable JSON against drift from Config/AbusedTlds.json, against the stored shape
# Invoke-AddTenantAllowBlockListTemplate writes, and against Microsoft's documented TLD syntax
# (sender: *.TLD; URL: *.TLD/*).
BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:ConfigRoot = Join-Path $BackendRoot 'Config'
    . (Join-Path $BackendRoot 'Modules/CIPPCore/Public/MailTriage/Get-CIPPAbusedTldCatalog.ps1')
    $script:Catalog = Get-CIPPAbusedTldCatalog -ConfigRoot $script:ConfigRoot
    $script:Split = { param($Entries) @($Entries -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
}

Describe 'Abused TLD catalog' {
    It 'has unique, lower-case TLDs with a risk rating each' {
        $Tlds = @($script:Catalog.Tlds.tld)
        $Tlds.Count | Should -BeGreaterThan 10
        ($Tlds | Sort-Object -Unique).Count | Should -Be $Tlds.Count
        foreach ($T in $script:Catalog.Tlds) {
            $T.tld | Should -MatchExactly '^[a-z]{2,}$'
            $T.senderRisk | Should -BeIn @('Low', 'Medium', 'High')
            $T.urlRisk | Should -BeIn @('Low', 'Medium', 'High')
            $T.note | Should -Not -BeNullOrEmpty
        }
    }

    It 'ships three templates with fixed, distinct GUIDs' {
        $script:Catalog.Templates.Count | Should -Be 3
        ($script:Catalog.Templates.GUID | Sort-Object -Unique).Count | Should -Be 3
        foreach ($G in $script:Catalog.Templates.GUID) { { [guid]::Parse($G) } | Should -Not -Throw }
    }

    It 'stores exactly the fields AddTenantAllowBlockListTemplate stores, plus GUID and description' {
        foreach ($T in $script:Catalog.Templates) {
            $Names = @($T.PSObject.Properties.Name | Sort-Object)
            $Names | Should -Be (@('description', 'entries', 'GUID', 'listMethod', 'listType', 'NoExpiration', 'notes', 'RemoveAfter', 'templateName') | Sort-Object)
            $T.listMethod | Should -Be 'Block'
            $T.NoExpiration | Should -BeTrue
            $T.RemoveAfter | Should -BeFalse
        }
    }
}

Describe 'Sender template' {
    BeforeAll { $script:Sender = $script:Catalog.Templates | Where-Object listType -EQ 'Sender' }

    It 'blocks every catalog TLD with the *.TLD syntax' {
        $Entries = & $script:Split $script:Sender.entries
        $Entries | Should -Be @($script:Catalog.Tlds.tld | ForEach-Object { "*.$_" })
    }

    It 'warns that a sender block also blocks outbound mail' {
        $script:Sender.description | Should -Match 'OUTBOUND'
        $script:Sender.notes | Should -Match 'OUTBOUND'
    }
}

Describe 'URL templates' {
    It 'cover every catalog TLD exactly once between them, with the *.TLD/* syntax' {
        $Url = @($script:Catalog.Templates | Where-Object listType -EQ 'Url')
        $Url.Count | Should -Be 2
        $All = @($Url | ForEach-Object { & $script:Split $_.entries })
        $All | ForEach-Object { $_ | Should -MatchExactly '^\*\.[a-z]{2,}/\*$' }
        ($All | ForEach-Object { $_ -replace '^\*\.|/\*$', '' } | Sort-Object) | Should -Be ($script:Catalog.Tlds.tld | Sort-Object)
    }

    It 'keeps the file-extension look-alikes (.zip, .mov) out of the main URL template' {
        $Main = $script:Catalog.Templates | Where-Object { $_.listType -eq 'Url' -and $_.templateName -notmatch 'zip' }
        (& $script:Split $Main.entries) | Should -Not -Contain '*.zip/*'
        (& $script:Split $Main.entries) | Should -Not -Contain '*.mov/*'
        $FileLike = $script:Catalog.Templates | Where-Object { $_.listType -eq 'Url' -and $_.templateName -match 'zip' }
        (& $script:Split $FileLike.entries) | Should -Be @('*.zip/*', '*.mov/*')
        $FileLike.templateName | Should -Match 'HIGH'
    }

    It 'only puts High URL-risk TLDs in the file-like template' {
        $High = @($script:Catalog.Tlds | Where-Object urlRisk -EQ 'High' | ForEach-Object { "*.$($_.tld)/*" })
        $FileLike = $script:Catalog.Templates | Where-Object { $_.listType -eq 'Url' -and $_.templateName -match 'zip' }
        (& $script:Split $FileLike.entries | Sort-Object) | Should -Be ($High | Sort-Object)
    }
}
