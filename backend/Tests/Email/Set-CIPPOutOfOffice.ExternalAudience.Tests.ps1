# Aspendora fork (Vikunja CIPP-40): Set-CIPPOutOfOffice -ExternalAudience. The Out-of-office Exposure page limits an
# exposed reply to known senders by sending only the state, schedule and ExternalAudience Known. Pins that this
# changes the audience without resending (and so without touching) either message, and that callers which do not
# pass the new parameter keep the old All / None rule.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Set-CIPPOutOfoffice.ps1')
    function New-ExoRequest { param($tenantid, $cmdlet, $cmdParams, $Anchor) }
    function Write-LogMessage { param($headers, $API, $message, $Sev, $tenant, $LogData) }
    function Get-CippException { param($Exception) @{ NormalizedError = "$Exception" } }
}

Describe 'Set-CIPPOutOfOffice ExternalAudience' {
    BeforeEach {
        $script:Params = $null
        Mock New-ExoRequest { $script:Params = $cmdParams }
        Mock Write-LogMessage {}
    }

    It 'keeps the old rule when no audience is given: All with an external message' {
        Set-CIPPOutOfOffice -UserID 'amy@contoso.com' -TenantFilter 'contoso.com' -State 'Enabled' -ExternalMessage 'Away' | Out-Null
        $script:Params.ExternalAudience | Should -Be 'All'
    }

    It 'keeps the old rule when no audience is given: None without an external message' {
        Set-CIPPOutOfOffice -UserID 'amy@contoso.com' -TenantFilter 'contoso.com' -State 'Disabled' | Out-Null
        $script:Params.ExternalAudience | Should -Be 'None'
    }

    It 'sets Known without sending either message, so Exchange keeps both' {
        Set-CIPPOutOfOffice -UserID 'amy@contoso.com' -TenantFilter 'contoso.com' -State 'Enabled' -ExternalAudience 'Known' | Out-Null
        $script:Params.ExternalAudience | Should -Be 'Known'
        $script:Params.AutoReplyState | Should -Be 'Enabled'
        $script:Params.Keys | Should -Not -Contain 'ExternalMessage'
        $script:Params.Keys | Should -Not -Contain 'InternalMessage'
    }

    It 'passes the existing schedule through unchanged for a Scheduled reply' {
        $Start = [datetime]::new(2026, 11, 3, 14, 0, 0)
        $End = [datetime]::new(2026, 11, 10, 14, 0, 0)
        Set-CIPPOutOfOffice -UserID 'amy@contoso.com' -TenantFilter 'contoso.com' -State 'Scheduled' -StartTime $Start -EndTime $End -ExternalAudience 'Known' | Out-Null
        $script:Params.ExternalAudience | Should -Be 'Known'
        $script:Params.StartTime | Should -Be $Start
        $script:Params.EndTime | Should -Be $End
        $script:Params.Keys | Should -Not -Contain 'CreateOOFEvent'
    }

    It 'lets an explicit audience win over the external-message rule' {
        Set-CIPPOutOfOffice -UserID 'amy@contoso.com' -TenantFilter 'contoso.com' -State 'Enabled' -ExternalMessage 'Away' -ExternalAudience 'Known' | Out-Null
        $script:Params.ExternalAudience | Should -Be 'Known'
    }

    It 'rejects an unknown audience' {
        { Set-CIPPOutOfOffice -UserID 'amy@contoso.com' -TenantFilter 'contoso.com' -State 'Enabled' -ExternalAudience 'Everyone' } | Should -Throw
    }
}
