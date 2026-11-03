# Pester tests for the ticket reference New-CippExtAlert hands to HaloPSA.
# A scheduled task's reference travels with the alert untouched; reading it is this extension's job
# because [ID:nnnn] is HaloPSA's own token - the same one it uses to thread emailed replies onto a
# ticket. When one is present the alert becomes a note on that ticket, and the affected-user lookup
# (plus the Graph call under it) is skipped, since the ticket already carries its end user.

BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Join-Path $BackendRoot 'Modules/CippExtensions/Public/New-CippExtAlert.ps1'

    function Get-CIPPTable { param([string]$TableName) }
    function Get-CIPPAzDataTableEntity { param($TableName, $Filter, $Property, $First) }
    function Get-Tenants { param($TenantFilter, [switch]$IncludeErrors) }
    function Add-CIPPAzDataTableEntity { param($TableName, $Entity, [switch]$Force) }
    function New-HaloPSATicket { param($Title, $Description, $Client, $UserUPN, $AzureOID, $DisplayName, $TicketId) }
    function New-GradientAlert { param($Title, $Description, $Client) }
    function New-ConnectWiseTicket { param($Title, $Description, $Client) }
    function Add-ConnectWiseTicketNote { param($TicketId, $Text, $ExpectedCompanyId, [switch]$RequireOpen, $Configuration) }
    function ConvertFrom-CIPPHtmlToText { param($Html) "text:$Html" }
    function New-GraphGetRequest { param($uri, $tenantid, $AsApp) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData, $headers) }

    . $FunctionPath

    function New-Alert {
        param($Reference, $AffectedUser, $PsaTicketId)
        $Alert = [pscustomobject]@{
            TenantId   = 'contoso.onmicrosoft.com'
            AlertTitle = '[CIPP] Scheduled Task - contoso - New user creation'
            AlertText  = '<p>body</p>'
        }
        if ($Reference) { $Alert | Add-Member -NotePropertyName Reference -NotePropertyValue $Reference }
        if ($PsaTicketId) { $Alert | Add-Member -NotePropertyName PsaTicketId -NotePropertyValue $PsaTicketId }
        if ($AffectedUser) { $Alert | Add-Member -NotePropertyName AffectedUser -NotePropertyValue $AffectedUser }
        $Alert
    }

    $script:NewStarter = [pscustomobject]@{ UPN = 'new.starter@contoso.com'; DisplayName = 'New Starter' }
}

Describe 'New-CippExtAlert - HaloPSA ticket reference' {
    BeforeEach {
        $script:TicketArgs = $null
        Mock -CommandName Get-CIPPTable -MockWith { param([string]$TableName) @{ TableName = $TableName } }
        Mock -CommandName Get-Tenants -MockWith { [pscustomobject]@{ customerId = 'customer-guid' } }
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName New-GraphGetRequest -MockWith { [pscustomobject]@{ id = 'oid-guid'; displayName = 'New Starter' } }
        # An explicit param block is required: a Pester mock body without one leaves
        # $PSBoundParameters empty, which silently passes every "was not passed" assertion.
        Mock -CommandName New-HaloPSATicket -MockWith {
            param($Title, $Description, $Client, $UserUPN, $AzureOID, $DisplayName, $TicketId)
            $script:TicketArgs = [pscustomobject]@{
                Title = $Title; Client = $Client; UserUPN = $UserUPN
                AzureOID = $AzureOID; DisplayName = $DisplayName; TicketId = $TicketId
            }
        }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            param($TableName, $Filter)
            if ($Filter -like '*HaloMapping*') { return [pscustomobject]@{ RowKey = 'customer-guid'; IntegrationId = 19 } }
            [pscustomobject]@{
                config = (@{ HaloPSA = @{ enabled = $true; LinkTicketsToUsers = $true } } | ConvertTo-Json -Depth 5)
            }
        }
    }

    Context 'The task carries an explicit ticket id' {
        It 'uses PsaTicketId when it is set' {
            # Set from the ticket box on the user / offboarding / scheduler forms.
            New-CippExtAlert -Alert (New-Alert -PsaTicketId 1380)

            $script:TicketArgs.TicketId | Should -Be 1380
        }

        It 'accepts it as a string, which is how the task row stores it' {
            New-CippExtAlert -Alert (New-Alert -PsaTicketId '1380')

            $script:TicketArgs.TicketId | Should -Be 1380
        }

        It 'wins over an [ID:] token in the reference' {
            New-CippExtAlert -Alert (New-Alert -PsaTicketId 1380 -Reference '[ID:99] older reference')

            $script:TicketArgs.TicketId | Should -Be 1380
        }

        It 'warns when the reference names a different ticket' {
            # The reference is what the notification title shows, so a mismatch puts the note on a
            # ticket the title never mentions - which reads as the feature not working at all.
            New-CippExtAlert -Alert (New-Alert -PsaTicketId 1380 -Reference '[ID:1376] Starter Creation')

            $script:TicketArgs.TicketId | Should -Be 1380
            Should -Invoke Write-LogMessage -Times 1 -Exactly -ParameterFilter {
                $sev -eq 'Warning' -and $message -like '*targets HaloPSA ticket 1380*' -and $message -like '*names ticket 1376*'
            }
        }

        It 'stays quiet when both name the same ticket' {
            New-CippExtAlert -Alert (New-Alert -PsaTicketId 1380 -Reference '[ID:1380] Starter Creation')

            $script:TicketArgs.TicketId | Should -Be 1380
            Should -Invoke Write-LogMessage -Times 0 -Exactly
        }

        It 'skips the contact lookup like any targeted ticket' {
            New-CippExtAlert -Alert (New-Alert -PsaTicketId 1380 -AffectedUser $script:NewStarter)

            Should -Invoke New-GraphGetRequest -Times 0 -Exactly
            $script:TicketArgs.UserUPN | Should -BeNullOrEmpty
        }

        It 'warns and raises a new ticket when the value is not a usable id' {
            New-CippExtAlert -Alert (New-Alert -PsaTicketId 'not-a-ticket')

            $script:TicketArgs.TicketId | Should -BeNullOrEmpty
            Should -Invoke Write-LogMessage -Times 1 -Exactly -ParameterFilter { $sev -eq 'Warning' -and $message -like '*not a usable HaloPSA ticket id*' }
        }
    }

    Context 'The reference names a ticket' {
        It 'passes the ticket id through to HaloPSA' {
            New-CippExtAlert -Alert (New-Alert -Reference '[ID:1380] Starter Creation of FirstName LastName')

            $script:TicketArgs.TicketId | Should -Be 1380
        }

        It 'finds the token wherever it sits in the reference' {
            New-CippExtAlert -Alert (New-Alert -Reference 'Starter Creation - see [ID:42] for detail')

            $script:TicketArgs.TicketId | Should -Be 42
        }

        It 'refuses a digit run too large to be a ticket id, and warns' {
            New-CippExtAlert -Alert (New-Alert -Reference '[ID:99999999999999999999]')

            $script:TicketArgs.TicketId | Should -BeNullOrEmpty
            Should -Invoke Write-LogMessage -Times 1 -Exactly -ParameterFilter { $sev -eq 'Warning' -and $message -like '*not a usable HaloPSA ticket id*' }
        }

        It 'skips the contact lookup and its Graph call' {
            New-CippExtAlert -Alert (New-Alert -Reference '[ID:1380] Starter' -AffectedUser $script:NewStarter)

            Should -Invoke New-GraphGetRequest -Times 0 -Exactly
            $script:TicketArgs.UserUPN | Should -BeNullOrEmpty
            $script:TicketArgs.AzureOID | Should -BeNullOrEmpty
        }
    }

    Context 'The reference names no ticket' {
        It 'sends no ticket id for a free-text reference' {
            New-CippExtAlert -Alert (New-Alert -Reference 'Starter Creation of FirstName LastName')

            $script:TicketArgs.TicketId | Should -BeNullOrEmpty
        }

        It 'sends no ticket id when there is no reference at all' {
            New-CippExtAlert -Alert (New-Alert)

            $script:TicketArgs.TicketId | Should -BeNullOrEmpty
        }

        It 'still resolves the affected user' {
            New-CippExtAlert -Alert (New-Alert -AffectedUser $script:NewStarter)

            Should -Invoke New-GraphGetRequest -Times 1 -Exactly
            $script:TicketArgs.UserUPN | Should -Be 'new.starter@contoso.com'
            $script:TicketArgs.AzureOID | Should -Be 'oid-guid'
        }

        It 'ignores a reference that merely contains digits' {
            # 'PO 1380' or 'INV-2024-1389' are free text, not a ticket number.
            New-CippExtAlert -Alert (New-Alert -Reference 'PO 1380')

            $script:TicketArgs.TicketId | Should -BeNullOrEmpty
        }

        It 'ignores a reference with digits embedded in an identifier' {
            New-CippExtAlert -Alert (New-Alert -Reference 'INV-2024-1389')

            $script:TicketArgs.TicketId | Should -BeNullOrEmpty
        }

        It 'ignores a bare number - a reference is free text, not a ticket id' {
            # Deliberate: order numbers, asset tags and change ids all live in this field, and
            # treating one as a ticket id would append a starter's password to an unrelated ticket.
            # [ID:nnnn] is required, which is also what Halo's own email threading matches on.
            New-CippExtAlert -Alert (New-Alert -Reference '1389')

            $script:TicketArgs.TicketId | Should -BeNullOrEmpty
        }

        It 'ignores a bare number with surrounding whitespace' {
            New-CippExtAlert -Alert (New-Alert -Reference '  1389  ')

            $script:TicketArgs.TicketId | Should -BeNullOrEmpty
        }
    }
}

Describe 'New-CippExtAlert - PSA consolidation key' {
    BeforeEach {
        $script:TicketArgs = $null
        $script:GradientArgs = $null

        Mock -CommandName Get-CIPPTable -MockWith {
            param([string]$TableName)
            @{ TableName = $TableName }
        }

        Mock -CommandName Get-Tenants -MockWith {
            [pscustomobject]@{
                customerId = 'customer-guid'
            }
        }

        Mock -CommandName Write-LogMessage -MockWith { }

        Mock -CommandName New-HaloPSATicket -MockWith {
            param(
                $Title,
                $Description,
                $Client,
                $UserUPN,
                $AzureOID,
                $DisplayName,
                $TicketPriority,
                $TicketId,
                $ConsolidationKey
            )

            $script:TicketArgs = [pscustomobject]@{
                Title            = $Title
                Client           = $Client
                ConsolidationKey = $ConsolidationKey
            }
        }

        Mock -CommandName New-GradientAlert -MockWith {
            param($Title, $Description, $Client)

            $script:GradientArgs = [pscustomobject]@{
                Title  = $Title
                Client = $Client
            }
        }
    }

    It 'passes the optional consolidation key to HaloPSA' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            param($TableName, $Filter)

            if ($Filter -like '*HaloMapping*') {
                return [pscustomobject]@{
                    RowKey        = 'customer-guid'
                    IntegrationId = 19
                }
            }

            [pscustomobject]@{
                config = (@{
                    HaloPSA = @{
                        enabled = $true
                    }
                } | ConvertTo-Json -Depth 5)
            }
        }

        $Alert = [pscustomobject]@{
            TenantId            = 'contoso.onmicrosoft.com'
            AlertTitle          = '[CIPP] dynamic title'
            AlertText           = '<p>body</p>'
            PSAConsolidationKey = 'contoso.com|Alerts'
        }

        New-CippExtAlert -Alert $Alert

        $script:TicketArgs.ConsolidationKey |
            Should -Be 'contoso.com|Alerts'
    }

    It 'does not change the Gradient call when the consolidation key is present' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            param($TableName, $Filter)

            [pscustomobject]@{
                config = (@{
                    Gradient = @{
                        enabled = $true
                    }
                } | ConvertTo-Json -Depth 5)
            }
        }

        $Alert = [pscustomobject]@{
            TenantId            = 'contoso.onmicrosoft.com'
            AlertTitle          = '[CIPP] dynamic title'
            AlertText           = '<p>body</p>'
            PSAConsolidationKey = 'contoso.com|Alerts'
        }

        New-CippExtAlert -Alert $Alert

        $script:GradientArgs.Title |
            Should -Be '[CIPP] dynamic title'

        $script:GradientArgs.Client |
            Should -Be 'contoso.onmicrosoft.com'
    }
}

Describe 'New-CippExtAlert - ConnectWise note on a referenced ticket' {
    BeforeEach {
        Mock -CommandName Get-CIPPTable -MockWith { param([string]$TableName) @{ TableName = $TableName } }
        Mock -CommandName Get-Tenants -MockWith { [pscustomobject]@{ defaultDomainName = 'contoso.com'; customerId = 'customer-guid' } }
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName New-ConnectWiseTicket -MockWith { 'Ticket created in ConnectWise: 1' }
        Mock -CommandName Add-ConnectWiseTicketNote -MockWith { [pscustomobject]@{ Success = $true; Message = 'Added an internal note to ConnectWise ticket 60047 (x).' } }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            param($TableName, $Filter)
            if ($Filter -like '*ConnectWiseMapping*') { return [pscustomobject]@{ RowKey = 'customer-guid'; IntegrationId = '250' } }
            [pscustomobject]@{ config = (@{ ConnectWise = @{ enabled = $true; BaseURL = 'https://cw.invalid' } } | ConvertTo-Json -Depth 5) }
        }
        $script:CwAlert = @{ TenantId = 'contoso.com'; AlertTitle = '[CIPP] SECURITY: New-TransportRule'; AlertText = '<p>body</p>'; ConnectWiseNoteTicketId = 60047 }
    }

    It 'adds a note and opens no ticket' {
        $Result = New-CippExtAlert -Alert $script:CwAlert

        $Result | Should -BeLike 'Added an internal note*'
        Should -Invoke New-ConnectWiseTicket -Times 0 -Exactly
    }

    It 'requires the ticket to be open and belong to the mapped company' {
        $null = New-CippExtAlert -Alert $script:CwAlert

        Should -Invoke Add-ConnectWiseTicketNote -Times 1 -Exactly -ParameterFilter { $TicketId -eq 60047 -and $ExpectedCompanyId -eq 250 -and $RequireOpen }
    }

    It 'keeps the alert title and readable text in the note, and says why it is there' {
        $null = New-CippExtAlert -Alert $script:CwAlert

        Should -Invoke Add-ConnectWiseTicketNote -Times 1 -Exactly -ParameterFilter {
            $Text -like '*SECURITY: New-TransportRule*' -and $Text -like '*text:<p>body</p>*' -and $Text -like '*instead of opening a new ticket*'
        }
    }

    It 'opens a ticket and warns when the note is refused' {
        Mock -CommandName Add-ConnectWiseTicketNote -MockWith { [pscustomobject]@{ Success = $false; Message = 'Ticket 60047 is closed. Nothing was posted.' } }

        $Result = New-CippExtAlert -Alert $script:CwAlert

        $Result | Should -Be 'Ticket created in ConnectWise: 1'
        Should -Invoke Write-LogMessage -Times 1 -Exactly -ParameterFilter { $sev -eq 'Warning' -and $message -like '*is closed*' }
    }

    It 'opens a ticket and warns when posting throws' {
        Mock -CommandName Add-ConnectWiseTicketNote -MockWith { throw 'network' }

        $null = New-CippExtAlert -Alert $script:CwAlert

        Should -Invoke New-ConnectWiseTicket -Times 1 -Exactly
        Should -Invoke Write-LogMessage -Times 1 -Exactly -ParameterFilter { $sev -eq 'Warning' -and $message -like '*network*' }
    }

    It 'opens a ticket as before when the alert names no ticket' {
        $script:CwAlert.Remove('ConnectWiseNoteTicketId')

        $null = New-CippExtAlert -Alert $script:CwAlert

        Should -Invoke Add-ConnectWiseTicketNote -Times 0 -Exactly
        Should -Invoke New-ConnectWiseTicket -Times 1 -Exactly
    }

    It 'does not let a scheduled task PsaTicketId redirect a ConnectWise alert' {
        # PsaTicketId is HaloPSA's; only the audit reference may turn a ConnectWise alert into a note.
        $script:CwAlert.Remove('ConnectWiseNoteTicketId')
        $script:CwAlert.PsaTicketId = 60047

        $null = New-CippExtAlert -Alert $script:CwAlert

        Should -Invoke Add-ConnectWiseTicketNote -Times 0 -Exactly
        Should -Invoke New-ConnectWiseTicket -Times 1 -Exactly
    }
}

Describe 'New-CippExtAlert - ConnectWise role grant ticket window' {
    BeforeAll {
        $script:WindowRow = $null
        function Set-WindowRow { param($MinutesAgo, $TicketID = '60300') $script:WindowRow = [pscustomobject]@{ TicketID = $TicketID; OpenedUtc = [datetimeoffset]::UtcNow.AddMinutes(-$MinutesAgo).ToString('o') } }
    }
    BeforeEach {
        $script:WindowRow = $null
        $script:SavedRow = $null
        Mock -CommandName Get-CIPPTable -MockWith { param([string]$TableName) @{ TableName = $TableName } }
        Mock -CommandName Get-Tenants -MockWith { [pscustomobject]@{ customerId = 'customer-guid'; defaultDomainName = 'contoso.com' } }
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName New-ConnectWiseTicket -MockWith { 'Ticket created in ConnectWise: 60400' }
        Mock -CommandName Add-ConnectWiseTicketNote -MockWith { [pscustomobject]@{ Success = $true; Message = 'Added an internal note to ConnectWise ticket 60300 (x).' } }
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith { param($TableName, $Entity, [switch]$Force) $script:SavedRow = $Entity }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            param($TableName, $Filter)
            if ($Filter -like '*ConnectWiseMapping*') { return [pscustomobject]@{ RowKey = 'customer-guid'; IntegrationId = '250' } }
            if ($Filter -like '*ConnectWiseAlertWindow*') { return $script:WindowRow }
            [pscustomobject]@{ config = (@{ ConnectWise = @{ enabled = $true; BaseURL = 'https://cw.invalid' } } | ConvertTo-Json -Depth 5) }
        }
        $script:GrantAlert = @{ TenantId = 'contoso.com'; AlertTitle = '[CIPP] SECURITY: Add member to role.'; AlertText = '<p>body</p>'; ConnectWiseTicketWindow = 'RoleGrant' }
    }

    It 'opens a ticket and records it when no window is open' {
        $Result = New-CippExtAlert -Alert ([pscustomobject]$script:GrantAlert)

        $Result | Should -Be 'Ticket created in ConnectWise: 60400'
        Should -Invoke Add-ConnectWiseTicketNote -Times 0 -Exactly
        $script:SavedRow.PartitionKey | Should -Be 'ConnectWiseAlertWindow'
        $script:SavedRow.RowKey | Should -Be '250-RoleGrant'
        $script:SavedRow.TicketID | Should -Be '60400'
    }

    It 'files a grant inside the hour as a note on the open window ticket' {
        Set-WindowRow -MinutesAgo 59
        New-CippExtAlert -Alert ([pscustomobject]$script:GrantAlert) | Out-Null

        Should -Invoke New-ConnectWiseTicket -Times 0 -Exactly
        Should -Invoke Add-CIPPAzDataTableEntity -Times 0 -Exactly
        Should -Invoke Add-ConnectWiseTicketNote -Times 1 -Exactly -ParameterFilter {
            $TicketId -eq 60300 -and $ExpectedCompanyId -eq 250 -and $RequireOpen -and $Text -like '*within the last hour*treat it as a security incident*text:<p>body</p>*'
        }
    }

    It 'opens a new ticket and starts a new window once the hour has passed' {
        Set-WindowRow -MinutesAgo 61
        New-CippExtAlert -Alert ([pscustomobject]$script:GrantAlert) | Out-Null

        Should -Invoke Add-ConnectWiseTicketNote -Times 0 -Exactly
        Should -Invoke New-ConnectWiseTicket -Times 1 -Exactly
        $script:SavedRow.TicketID | Should -Be '60400'
    }

    It 'opens a new ticket without a warning when the window ticket was closed' {
        Set-WindowRow -MinutesAgo 5
        Mock -CommandName Add-ConnectWiseTicketNote -MockWith { [pscustomobject]@{ Success = $false; Message = 'Ticket 60300 is closed. Nothing was posted.' } }
        New-CippExtAlert -Alert ([pscustomobject]$script:GrantAlert) | Out-Null

        Should -Invoke New-ConnectWiseTicket -Times 1 -Exactly
        $script:SavedRow.TicketID | Should -Be '60400'
        Should -Invoke Write-LogMessage -Times 0 -Exactly -ParameterFilter { $sev -eq 'Warning' }
    }

    It 'opens a ticket and warns when ConnectWise refuses for another reason' {
        Set-WindowRow -MinutesAgo 5
        Mock -CommandName Add-ConnectWiseTicketNote -MockWith { [pscustomobject]@{ Success = $false; Message = "Ticket 60300 belongs to 'Other'" } }
        New-CippExtAlert -Alert ([pscustomobject]$script:GrantAlert) | Out-Null

        Should -Invoke New-ConnectWiseTicket -Times 1 -Exactly
        Should -Invoke Write-LogMessage -Times 1 -Exactly -ParameterFilter { $sev -eq 'Warning' }
    }

    It 'opens a ticket when the window row is unreadable or the table fails' {
        $script:WindowRow = [pscustomobject]@{ TicketID = '60300'; OpenedUtc = 'not a date' }
        New-CippExtAlert -Alert ([pscustomobject]$script:GrantAlert) | Out-Null
        Should -Invoke New-ConnectWiseTicket -Times 1 -Exactly
        Should -Invoke Write-LogMessage -Times 1 -Exactly -ParameterFilter { $sev -eq 'Warning' }
    }

    It 'keeps the ticket when the window cannot be saved' {
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith { throw 'table down' }
        $Result = New-CippExtAlert -Alert ([pscustomobject]$script:GrantAlert)

        $Result | Should -Be 'Ticket created in ConnectWise: 60400'
        Should -Invoke Write-LogMessage -Times 1 -Exactly -ParameterFilter { $sev -eq 'Warning' }
    }

    It 'records no window when the ticket could not be created' {
        Mock -CommandName New-ConnectWiseTicket -MockWith { 'Failed to send ticket to ConnectWise: 500' }
        $Result = New-CippExtAlert -Alert ([pscustomobject]$script:GrantAlert)

        $Result | Should -Be 'Failed to send ticket to ConnectWise: 500'
        Should -Invoke Add-CIPPAzDataTableEntity -Times 0 -Exactly
    }

    It 'never reads a window for an alert that did not ask for one' {
        $script:GrantAlert.Remove('ConnectWiseTicketWindow')
        Set-WindowRow -MinutesAgo 5
        New-CippExtAlert -Alert ([pscustomobject]$script:GrantAlert) | Out-Null

        Should -Invoke Add-ConnectWiseTicketNote -Times 0 -Exactly
        Should -Invoke New-ConnectWiseTicket -Times 1 -Exactly
        Should -Invoke Add-CIPPAzDataTableEntity -Times 0 -Exactly
    }
}

Describe 'New-CippExtAlert - HaloPSA ignores the ConnectWise note ticket' {
    It 'still opens a Halo ticket' {
        Mock -CommandName Get-CIPPTable -MockWith { param([string]$TableName) @{ TableName = $TableName } }
        Mock -CommandName Get-Tenants -MockWith { [pscustomobject]@{ customerId = 'customer-guid' } }
        Mock -CommandName Write-LogMessage -MockWith { }
        $script:HaloTicketId = 'unset'
        Mock -CommandName New-HaloPSATicket -MockWith { param($Title, $Description, $Client, $UserUPN, $AzureOID, $DisplayName, $TicketId) $script:HaloTicketId = $TicketId }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            param($TableName, $Filter)
            if ($Filter -like '*HaloMapping*') { return [pscustomobject]@{ RowKey = 'customer-guid'; IntegrationId = 19 } }
            [pscustomobject]@{ config = (@{ HaloPSA = @{ enabled = $true } } | ConvertTo-Json -Depth 5) }
        }

        New-CippExtAlert -Alert ([pscustomobject]@{ TenantId = 'contoso.com'; AlertTitle = 't'; AlertText = 'b'; ConnectWiseNoteTicketId = 60047 })

        $script:HaloTicketId | Should -BeNullOrEmpty
    }
}
