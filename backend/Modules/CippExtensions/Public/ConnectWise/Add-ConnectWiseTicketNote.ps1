function Add-ConnectWiseTicketNote {
    <#
    .SYNOPSIS
        Adds a note to an existing ConnectWise Manage ticket by number.
    .DESCRIPTION
        New-ConnectWiseTicket only adds notes to tickets it opened itself (ConsolidateTickets); this posts to any
        ticket number. It reads the ticket first and refuses when the ticket is missing, or belongs to a different
        company than ExpectedCompanyId (the tenant's ConnectWise mapping), so evidence for one client cannot land on
        another client's ticket. Default note type is Internal Analysis (internal, not on the customer portal);
        processNotifications is false so ConnectWise sends no email (Aspendora's Email Bridge mails Discussion notes
        itself). Uses the CIPP ConnectWise extension's stored credentials. Returns a result object; never throws for
        API errors. Aspendora fork addition (Vikunja CIPP-38).
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][int]$TicketId,
        [Parameter(Mandatory)][string]$Text,
        [ValidateSet('Internal', 'Discussion')][string]$NoteType = 'Internal',
        [int]$ExpectedCompanyId = 0,
        $Configuration
    )

    if (-not $Configuration) {
        $Table = Get-CIPPTable -TableName Extensionsconfig
        $Configuration = ((Get-CIPPAzDataTableEntity @Table).config | ConvertFrom-Json).ConnectWise
    }
    if (-not $Configuration -or $Configuration.Enabled -eq $false -or -not $Configuration.BaseURL) {
        return [pscustomobject]@{ Success = $false; TicketId = $TicketId; Message = 'The ConnectWise Manage integration is not configured or not enabled (Settings > Integrations > ConnectWise).' }
    }
    try {
        $Headers = Get-ConnectWiseHeaders -Configuration $Configuration
    } catch {
        return [pscustomobject]@{ Success = $false; TicketId = $TicketId; Message = "ConnectWise credentials are incomplete: $($_.Exception.Message)" }
    }
    $BaseURL = "$($Configuration.BaseURL)/v4_6_release/apis/3.0"
    $ErrorText = {
        param($Err)
        if ($Err.ErrorDetails.Message) { Get-NormalizedError -Message $Err.ErrorDetails.Message } else { $Err.Exception.Message }
    }

    try {
        $Ticket = Invoke-RestMethod -AllowInsecureRedirect -Uri "$BaseURL/service/tickets/$($TicketId)?fields=id,summary,company,closedFlag,board,status" -Method GET -Headers $Headers
    } catch {
        return [pscustomobject]@{ Success = $false; TicketId = $TicketId; Message = "Could not read ConnectWise ticket $($TicketId): $(& $ErrorText $_)" }
    }
    if (-not $Ticket.id) {
        return [pscustomobject]@{ Success = $false; TicketId = $TicketId; Message = "ConnectWise ticket $TicketId was not found." }
    }
    if ($ExpectedCompanyId -gt 0 -and [int]$Ticket.company.id -ne $ExpectedCompanyId) {
        return [pscustomobject]@{ Success = $false; TicketId = $TicketId; Message = "Ticket $TicketId belongs to '$($Ticket.company.name)' (company $($Ticket.company.id)), not the company this tenant is mapped to ($ExpectedCompanyId). Nothing was posted." }
    }

    $Note = [ordered]@{
        text                  = $Text
        detailDescriptionFlag = $NoteType -eq 'Discussion'
        internalAnalysisFlag  = $NoteType -eq 'Internal'
        resolutionFlag        = $false
        internalFlag          = $NoteType -eq 'Internal'
        processNotifications  = $false
    } | ConvertTo-Json -Compress

    try {
        if ($PSCmdlet.ShouldProcess("ConnectWise ticket $TicketId", 'Add note')) {
            $Created = Invoke-RestMethod -AllowInsecureRedirect -Uri "$BaseURL/service/tickets/$TicketId/notes" -Method POST -Headers $Headers -Body $Note
            return [pscustomobject]@{ Success = $true; TicketId = $TicketId; NoteId = $Created.id; Company = $Ticket.company.name; Summary = $Ticket.summary; Closed = [bool]$Ticket.closedFlag; Message = "Added an $($NoteType.ToLower()) note to ConnectWise ticket $TicketId ($($Ticket.summary))$(if ($Ticket.closedFlag) { ' - note: the ticket is closed' })." }
        }
        return [pscustomobject]@{ Success = $false; TicketId = $TicketId; Message = 'WhatIf: nothing posted.' }
    } catch {
        $Message = & $ErrorText $_
        Write-LogMessage -message "Failed to add note to ConnectWise ticket $($TicketId): $Message" -API 'ConnectWiseTicket' -sev Error -LogData (Get-CippException -Exception $_)
        return [pscustomobject]@{ Success = $false; TicketId = $TicketId; Message = "Failed to add note to ConnectWise ticket $($TicketId): $Message" }
    }
}
