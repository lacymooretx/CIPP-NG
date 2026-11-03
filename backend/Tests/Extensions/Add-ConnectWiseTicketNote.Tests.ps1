# Aspendora fork (Vikunja CIPP-38): posting a note to an existing ConnectWise ticket by number.
BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $BackendRoot 'Modules/CippExtensions/Public/ConnectWise/Add-ConnectWiseTicketNote.ps1')
    function Get-CIPPTable { param([string]$TableName) }
    function Get-CIPPAzDataTableEntity { param($TableName, $Filter) }
    function Get-ConnectWiseHeaders { param($Configuration) @{ Authorization = 'Basic x' } }
    function Get-NormalizedError { param($Message) $Message }
    function Get-CippException { param($Exception) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData, $headers) }
    $script:Config = [pscustomobject]@{ BaseURL = 'https://cw.example.com'; Enabled = $true; CompanyID = 'x'; PublicKey = 'y' }
}

Describe 'Add-ConnectWiseTicketNote' {
    BeforeEach {
        $script:Posted = $null
        Mock Invoke-RestMethod -ParameterFilter { $Method -eq 'GET' } { [pscustomobject]@{ id = 60001; summary = 'Mail missing'; company = [pscustomobject]@{ id = 250; name = 'Contoso' }; closedFlag = $false } }
        Mock Invoke-RestMethod -ParameterFilter { $Method -eq 'POST' } { $script:Posted = @{ Uri = $Uri; Body = ($Body | ConvertFrom-Json) }; [pscustomobject]@{ id = 999 } }
    }

    It 'posts an internal-analysis note with notifications off' {
        $R = Add-ConnectWiseTicketNote -TicketId 60001 -Text 'evidence' -Configuration $script:Config -ExpectedCompanyId 250
        $R.Success | Should -BeTrue
        $R.NoteId | Should -Be 999
        $script:Posted.Uri | Should -Be 'https://cw.example.com/v4_6_release/apis/3.0/service/tickets/60001/notes'
        $script:Posted.Body.text | Should -Be 'evidence'
        $script:Posted.Body.internalAnalysisFlag | Should -BeTrue
        $script:Posted.Body.detailDescriptionFlag | Should -BeFalse
        $script:Posted.Body.processNotifications | Should -BeFalse
    }

    It 'refuses a ticket that belongs to another company and posts nothing' {
        $R = Add-ConnectWiseTicketNote -TicketId 60001 -Text 'evidence' -Configuration $script:Config -ExpectedCompanyId 777
        $R.Success | Should -BeFalse
        $R.Message | Should -Match 'not the company this tenant is mapped to'
        Should -Invoke Invoke-RestMethod -ParameterFilter { $Method -eq 'POST' } -Times 0 -Exactly
    }

    It 'refuses a closed ticket when asked to, and posts nothing' {
        Mock Invoke-RestMethod -ParameterFilter { $Method -eq 'GET' } { [pscustomobject]@{ id = 60001; summary = 'Done'; company = [pscustomobject]@{ id = 250; name = 'Contoso' }; closedFlag = $true } }
        $R = Add-ConnectWiseTicketNote -TicketId 60001 -Text 'evidence' -Configuration $script:Config -RequireOpen
        $R.Success | Should -BeFalse
        $R.Message | Should -Match 'is closed'
        Should -Invoke Invoke-RestMethod -ParameterFilter { $Method -eq 'POST' } -Times 0 -Exactly
    }

    It 'reports a missing ticket instead of throwing' {
        Mock Invoke-RestMethod -ParameterFilter { $Method -eq 'GET' } { throw 'Not Found' }
        $R = Add-ConnectWiseTicketNote -TicketId 1 -Text 'evidence' -Configuration $script:Config
        $R.Success | Should -BeFalse
        $R.Message | Should -Match 'Could not read ConnectWise ticket 1'
    }

    It 'says so when the integration is not configured' {
        $R = Add-ConnectWiseTicketNote -TicketId 1 -Text 'x' -Configuration ([pscustomobject]@{ Enabled = $false })
        $R.Success | Should -BeFalse
        $R.Message | Should -Match 'not configured or not enabled'
    }
}
