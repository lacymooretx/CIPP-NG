# Aspendora fork (Vikunja CIPP-32): the alert body for an email security / TABL / transport rule change - actor, IP,
# cmdlet, parameters, cached before-values and the "drift: <standard>" lines. Nothing is reverted.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Webhooks/Get-CIPPEmailSecurityChangeContext.ps1')

    function New-CIPPDbRequest { param($TenantFilter, $Type, $Fields) }
    function Get-CIPPStandards { param($TenantFilter) }
    function Get-CippTable { param($tablename) @{ TableName = $tablename } }
    function Get-CIPPAzDataTableEntity { param($TableName, $Context, $Filter) }

    function New-Data {
        param([string]$Operation, [object[]]$Parameters, [string]$Id = 'rec-1')
        [pscustomobject]@{
            Id             = $Id
            Operation      = $Operation
            CreationTime   = '2026-10-31T17:00:00Z'
            ResultStatus   = 'True'
            UserId         = 'admin@contoso.com'
            CIPPUserId     = $null
            ClientIP       = '203.0.113.7'
            CIPPIPDetected = '203.0.113.7'
            CIPPActorClass = 'Tenant'
            CIPPActorDetail = 'admin@contoso.com'
            ObjectId       = 'Default'
            CIPPParameters = (ConvertTo-Json -InputObject @($Parameters) -Compress)
        }
    }
}

Describe 'Get-CIPPEmailSecurityChangeContext' {
    BeforeEach {
        $script:EmailSecurityContextMemo = $null
        Mock New-CIPPDbRequest { @() }
        Mock Get-CIPPStandards { @() }
        Mock Get-CIPPAzDataTableEntity { @() }
    }

    It 'returns nothing for an operation outside the email security map' {
        Get-CIPPEmailSecurityChangeContext -Data (New-Data 'Set-InboxRule' @()) -Tenant 'contoso.com' | Should -BeNullOrEmpty
        Get-CIPPEmailSecurityChangeContext -Data (New-Data 'Add member to role.' @()) -Tenant 'contoso.com' | Should -BeNullOrEmpty
        Should -Invoke New-CIPPDbRequest -Times 0
    }

    It 'shows actor, IP, cmdlet and parameters, with before values from the cache' {
        Mock New-CIPPDbRequest { @([pscustomobject]@{ Identity = 'Default'; Name = 'Default'; AllowedSenderDomains = @('fabrikam.com') }) } -ParameterFilter { $Type -eq 'ExoHostedContentFilterPolicy' }
        $Data = New-Data 'Set-HostedContentFilterPolicy' @(@{ Name = 'Identity'; Value = 'Default' }, @{ Name = 'AllowedSenderDomains'; Value = 'evil.example' })
        $C = Get-CIPPEmailSecurityChangeContext -Data $Data -Tenant 'contoso.com'
        $C.Kind | Should -Be 'Anti-spam (inbound) policy'
        $C.Identity | Should -Be 'Default'
        $C.Title | Should -Match 'Set-HostedContentFilterPolicy'
        $C.Title | Should -Match 'admin@contoso.com'
        $C.IntroText | Should -Match '203\.0\.113\.7'
        $C.IntroText | Should -Match 'evil\.example'
        @($C.Before).Count | Should -Be 1
        $C.Before[0].Before | Should -Be 'fabrikam.com'
        $C.Before[0].After | Should -Be 'evil.example'
    }

    It 'says when the previous value is unknown' {
        $C = Get-CIPPEmailSecurityChangeContext -Data (New-Data 'Set-AntiPhishPolicy' @(@{ Name = 'Identity'; Value = 'Office365 AntiPhish Default' }, @{ Name = 'Enabled'; Value = 'False' })) -Tenant 'contoso.com'
        @($C.Before).Count | Should -Be 0
        $C.IntroText | Should -Match 'previous values are not known'
    }

    It 'adds a drift line, with the template name, for each standard that manages the object type' {
        Mock Get-CIPPStandards { @([pscustomobject]@{ Standard = 'TransportRuleTemplate'; TemplateId = 't1' }, [pscustomobject]@{ Standard = 'AuditLog'; TemplateId = 't1' }) }
        Mock Get-CIPPAzDataTableEntity { @([pscustomobject]@{ RowKey = 't1'; JSON = '{"templateName":"Aspendora Mail Flow"}' }) }
        $C = Get-CIPPEmailSecurityChangeContext -Data (New-Data 'Disable-TransportRule' @(@{ Name = 'Identity'; Value = 'Block external auto-forwarding' })) -Tenant 'contoso.com'
        @($C.Drift).Count | Should -Be 1
        $C.Drift[0] | Should -Be "drift: Transport Rule Template (standards.TransportRuleTemplate, template 'Aspendora Mail Flow')"
        $C.IntroText | Should -Match 'CIPP has not reverted anything'
    }

    It 'reports no drift when no standard manages the object type' {
        Mock Get-CIPPStandards { @([pscustomobject]@{ Standard = 'AuditLog'; TemplateId = 't1' }) }
        $C = Get-CIPPEmailSecurityChangeContext -Data (New-Data 'New-TenantAllowBlockListItems' @(@{ Name = 'ListType'; Value = 'Sender' }, @{ Name = 'Entries'; Value = 'bad@evil.example' })) -Tenant 'contoso.com'
        @($C.Drift).Count | Should -Be 0
        $C.IntroText | Should -Match 'there is no previous value'
    }

    It 'memoises per record so the json, html and psa renders look up once' {
        $Data = New-Data 'Set-MalwareFilterPolicy' @(@{ Name = 'Identity'; Value = 'Default' }) 'memo-1'
        $null = Get-CIPPEmailSecurityChangeContext -Data $Data -Tenant 'contoso.com'
        $null = Get-CIPPEmailSecurityChangeContext -Data $Data -Tenant 'contoso.com'
        Should -Invoke Get-CIPPStandards -Times 1 -Exactly
    }

    It 'html-encodes values taken from the audit record' {
        $C = Get-CIPPEmailSecurityChangeContext -Data (New-Data 'Set-SafeLinksPolicy' @(@{ Name = 'Identity'; Value = '<script>x</script>' })) -Tenant 'contoso.com'
        $C.IntroText | Should -Not -Match '<script>'
    }
}
