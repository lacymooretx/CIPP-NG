# Pester tests for the ConnectWise ticket summary length guard in New-ConnectWiseTicket.
# CW rejects a ticket outright (MaxLengthField) when summary exceeds 100 chars, and audit-log alert
# subjects such as "Add member to role. in <tenant> by ServicePrincipal_<guid>" exceed that, so the
# alert email sent but no ticket was created. The summary is truncated; the full title moves into the
# description and stays the consolidation key.

BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $BackendRoot 'Modules/CippExtensions/Public/ConnectWise/New-ConnectWiseTicket.ps1'

    function Get-CIPPTable { param([string]$TableName) }
    function Get-CIPPAzDataTableEntity { param($TableName, $Filter, $Property, $First) }
    function Add-CIPPAzDataTableEntity { param($TableName, $Entity, [switch]$Force) }
    function Get-ConnectWiseHeaders { param($Configuration) }
    function ConvertFrom-CIPPHtmlToText { param($Html) $Html }
    function Get-StringHash { param($String) }
    function Get-NormalizedError { param($Message) }
    function Get-CippException { param($Exception) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData, $headers) }

    . $FunctionPath

    function Get-TicketPayload {
        param([string]$Title)
        $script:CapturedBody = $null
        New-ConnectWiseTicket -Title $Title -Description 'body' -Client 250 | Out-Null
        $script:CapturedBody | ConvertFrom-Json
    }
}

Describe 'New-ConnectWiseTicket - summary length' {
    BeforeEach {
        Mock -CommandName Get-CIPPTable -MockWith { @{ TableName = 'x' } }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            [pscustomobject]@{ config = (@{ ConnectWise = @{ BaseURL = 'https://cw.example.com'; ConsolidateTickets = $true } } | ConvertTo-Json -Depth 5) }
        } -ParameterFilter { -not $Filter }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith { $null } -ParameterFilter { $Filter }
        Mock -CommandName Get-StringHash -MockWith { "hash:$String" }
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith { $script:SavedEntity = $Entity }
        Mock -CommandName Invoke-RestMethod -MockWith {
            $script:CapturedBody = $Body
            [pscustomobject]@{ id = 12345 }
        }
    }

    It 'leaves a short title untouched' {
        $Payload = Get-TicketPayload -Title 'Short alert'
        $Payload.summary | Should -Be 'Short alert'
        $Payload.initialDescription | Should -Be 'body'
    }

    It 'keeps a title of exactly 100 chars' {
        $Title = 'a' * 100
        (Get-TicketPayload -Title $Title).summary | Should -Be $Title
    }

    It 'truncates a long title to 100 chars and puts the full title in the description' {
        $Title = 'Add member to role. in 3endt.com by ServicePrincipal_4e9e491a-0000-0000-0000-000000000000 (SECURITY alert)'
        $Payload = Get-TicketPayload -Title $Title
        $Payload.summary.Length | Should -Be 100
        $Payload.summary | Should -BeLike '*...'
        $Payload.initialDescription | Should -Be "$Title`n`nbody"
    }

    It 'keys consolidation on the full title, not the truncated one' {
        $Title = 'b' * 150
        Get-TicketPayload -Title $Title | Out-Null
        Should -Invoke Get-StringHash -ParameterFilter { $String -eq $Title }
        $script:SavedEntity.RowKey | Should -Be "250-hash:$Title"
    }
}
